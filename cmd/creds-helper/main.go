package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"go.uber.org/zap"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}

	kc, err := getKubeClient(logger)
	if err != nil {
		logger.Fatal("error getting k8s client", zap.Error(err))
	}

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		logger.Fatal("failed to load AWS config", zap.Error(err))
	}

	stsClient := sts.NewFromConfig(cfg)

	output, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		logger.Fatal("failed to get caller identity", zap.Error(err))
	}

	awsAccountId := *output.Account
	awsRegion := cfg.Region

	logger.Info("starting", zap.String("aws_account_id", awsAccountId), zap.String("aws_region", awsRegion))

	ecrClient := ecr.NewFromConfig(cfg)

	credsHelperNamespace := os.Getenv("CREDS_HELPER_NAMESPACE")
	if credsHelperNamespace == "" {
		credsHelperNamespace = "default"
	}

	credsHelperSecretName := os.Getenv("CREDS_HELPER_SECRET_NAME")
	if credsHelperSecretName == "" {
		credsHelperSecretName = "ecr-creds"
	}

	helpercfg := &HelperConfig{
		Namespace:  credsHelperNamespace,
		SecretName: credsHelperSecretName,
		ReauthTime: 1 * time.Hour,
	}

	helper := NewHelper(logger, kc, ecrClient, helpercfg)
	helper.Run(context.Background())
}

func getKubeClient(logger *zap.Logger) (*kubernetes.Clientset, error) {
	var client *kubernetes.Clientset

	var kubeconfig string
	kubeconfigExists := false
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
		_, err := os.Stat(kubeconfig)
		kubeconfigExists = !os.IsNotExist(err)
	}

	if len(kubeconfig) > 0 && kubeconfigExists {
		logger.Info("using out of cluster config", zap.String("file", kubeconfig))

		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("error building config: %w", err)
		}

		client, err = kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, err
		}
	} else {
		logger.Info("using in cluster config")

		cfg, err := rest.InClusterConfig()
		if err != nil {
			return nil, err
		}

		client, err = kubernetes.NewForConfig(cfg)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

type HelperConfig struct {
	Namespace  string
	SecretName string
	ReauthTime time.Duration
}

func NewHelper(logger *zap.Logger, kc *kubernetes.Clientset, ecrClient *ecr.Client, cfg *HelperConfig) *Helper {
	return &Helper{
		logger:    logger,
		kc:        kc,
		ecrClient: ecrClient,
		cfg:       cfg,
	}
}

type Helper struct {
	logger    *zap.Logger
	kc        *kubernetes.Clientset
	ecrClient *ecr.Client
	cfg       *HelperConfig
}

func (h *Helper) Run(ctx context.Context) {
	h.logger.Info("running", zap.Duration("reauth_time", h.cfg.ReauthTime))

	for {
		if err := h.run(ctx); err != nil {
			h.logger.Error("error occurred", zap.Error(err))
		}
		time.Sleep(h.cfg.ReauthTime)
	}
}

type dockerConfigJSONAuth struct {
	Auth  string `json:"auth"`
	Email string `json:"email"`
}

type dockerConfigJSON struct {
	Auths map[string]dockerConfigJSONAuth `json:"auths,omitempty"`
}

func (h *Helper) run(ctx context.Context) error {
	tokenOutput, err := h.ecrClient.GetAuthorizationToken(ctx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		return fmt.Errorf("failed to get ecr authorization token: %w", err)
	}

	auths := map[string]dockerConfigJSONAuth{}
	for _, d := range tokenOutput.AuthorizationData {
		auths[*d.ProxyEndpoint] = dockerConfigJSONAuth{
			Auth:  *d.AuthorizationToken,
			Email: "none",
		}
	}

	data, err := json.Marshal(dockerConfigJSON{Auths: auths})
	if err != nil {
		return fmt.Errorf("error marshalling config: %w", err)
	}

	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: h.cfg.SecretName,
		},
		Data: map[string][]byte{".dockerconfigjson": data},
		Type: "kubernetes.io/dockerconfigjson",
	}

	_, err = h.kc.CoreV1().Secrets(h.cfg.Namespace).Get(ctx, h.cfg.SecretName, metav1.GetOptions{})
	if err != nil {
		if errors.IsNotFound(err) {
			h.logger.Debug("creating secret", zap.String("name", h.cfg.SecretName))

			_, err = h.kc.CoreV1().Secrets(h.cfg.Namespace).Create(ctx, secret, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("error creating secret: %w", err)
			}

			return nil
		} else {
			return fmt.Errorf("error getting secret: %w", err)
		}
	}

	h.logger.Debug("updating secret", zap.String("name", h.cfg.SecretName))

	_, err = h.kc.CoreV1().Secrets(h.cfg.Namespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("error updating secret: %w", err)
	}

	return nil
}
