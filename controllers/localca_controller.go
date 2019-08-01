/*
Copyright 2019 The cert-manager authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"k8s.io/client-go/tools/record"

	"github.com/go-logr/logr"
	core "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	exampleapi "github.com/jetstack/cert-manager-external-issuer-example/api/v1beta1"
	"github.com/jetstack/cert-manager-external-issuer-example/pkiutil"
)

// LocalCAReconciler reconciles a LocalCA object
type LocalCAReconciler struct {
	client.Client
	Log      logr.Logger
	Clock    clock.Clock
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=certmanager.example.com,resources=localcas,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certmanager.example.com,resources=localcas/status,verbs=get;update;patch

func (r *LocalCAReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("localca", req.NamespacedName)

	// Fetch the LocalCA resource being synced
	localCA := exampleapi.LocalCA{}
	if err := r.Client.Get(ctx, req.NamespacedName, &localCA); err != nil {
		log.Error(err, "failed to retrieve LocalCA resource")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Fetch the CA Secret
	caSecret := core.Secret{}
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: localCA.Spec.SecretName}, &caSecret); err != nil {
		log.Error(err, "failed to retrieve LocalCA resource")
		if apierrors.IsNotFound(err) {
			err := r.setLocalCAStatus(ctx, log, &localCA, exampleapi.ConditionFalse, "NotFound", "Failed to retrieve CA Secret: %v", err)
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, err
	}

	pk, cert, err := decodeCertificateSecret(&caSecret)
	if err != nil {
		log.Error(err, "failed to decode keypair")
		err := r.setLocalCAStatus(ctx, log, &localCA, exampleapi.ConditionFalse, "InvalidData", "Failed to decode CA secret data: %v", err)
		return ctrl.Result{}, err
	}

	// Validate the private key's public component is valid for the Certificate
	matches, err := pkiutil.PublicKeyMatchesCertificate(pk.Public(), cert)
	if err != nil {
		log.Error(err, "failed to validate private key is valid for certificate")
		err := r.setLocalCAStatus(ctx, log, &localCA, exampleapi.ConditionFalse, "BadKeyPair", "Failed to validate private key for certificate: %v", err)
		return ctrl.Result{}, err
	}
	if !matches {
		err := r.setLocalCAStatus(ctx, log, &localCA, exampleapi.ConditionFalse, "BadKeyPair", "Private key is not valid for certificate: %v", err)
		return ctrl.Result{}, err
	}

	// Check if the CA certificate is valid for signing
	if !cert.IsCA && pkiutil.CertificateHasKeyUsage(cert, x509.KeyUsageCertSign) {
		err := r.setLocalCAStatus(ctx, log, &localCA, exampleapi.ConditionFalse, "BadCertificate", "Certificate is not marked for certificate signing")
		return ctrl.Result{}, err
	}

	return ctrl.Result{}, r.setLocalCAStatus(ctx, log, &localCA, exampleapi.ConditionTrue, "Verified", "Signing CA verified and ready to issue certificates")
}

func decodeCertificateSecret(s *core.Secret) (crypto.Signer, *x509.Certificate, error) {
	// Attempt to read the CA keypair from the Secret resource
	if s.Data == nil {
		return nil, nil, fmt.Errorf("no private key or certificate data found in secret %s/%s", s.Namespace, s.Name)
	}

	pkBytes := s.Data[core.TLSPrivateKeyKey]
	certBytes := s.Data[core.TLSCertKey]

	if len(pkBytes) == 0 {
		return nil, nil, errors.New("missing private key data")
	}
	if len(certBytes) == 0 {
		return nil, nil, errors.New("missing certificate data")
	}

	// Attempt to decode the private key
	pk, err := pkiutil.DecodePrivateKeyBytes(pkBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode private key data: %v", err)
	}

	// Attempt to decode the certificate
	cert, err := pkiutil.DecodeX509CertificateBytes(certBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode certificate data: %v", err)
	}

	return pk, cert, nil
}

func (r *LocalCAReconciler) setLocalCAStatus(ctx context.Context, log logr.Logger, localCA *exampleapi.LocalCA, status exampleapi.ConditionStatus, reason, message string, args ...interface{}) error {
	// Format the message and update the localCA variable with the new Condition
	completeMessage := fmt.Sprintf(message, args...)
	r.setLocalCACondition(log, localCA, exampleapi.LocalCAConditionReady, status, reason, completeMessage)

	// Fire an Event to additionally inform users of the change
	eventType := core.EventTypeNormal
	if status == exampleapi.ConditionFalse {
		eventType = core.EventTypeWarning
	}
	r.Recorder.Event(localCA, eventType, reason, completeMessage)

	// Actually update the LocalCA resource
	return r.Client.Status().Update(ctx, localCA)
}

// setLocalCACondition will set a 'condition' on the given LocalCA.
// - If no condition of the same type already exists, the condition will be
//   inserted with the LastTransitionTime set to the current time.
// - If a condition of the same type and state already exists, the condition
//   will be updated but the LastTransitionTime will not be modified.
// - If a condition of the same type and different state already exists, the
//   condition will be updated and the LastTransitionTime set to the current
//   time.
func (r *LocalCAReconciler) setLocalCACondition(log logr.Logger, localCA *exampleapi.LocalCA, conditionType exampleapi.LocalCAConditionType, status exampleapi.ConditionStatus, reason, message string) {
	newCondition := exampleapi.LocalCACondition{
		Type:    conditionType,
		Status:  status,
		Reason:  reason,
		Message: message,
	}

	nowTime := metav1.NewTime(r.Clock.Now())
	newCondition.LastTransitionTime = &nowTime

	// Search through existing conditions
	for idx, cond := range localCA.Status.Conditions {
		// Skip unrelated conditions
		if cond.Type != conditionType {
			continue
		}

		// If this update doesn't contain a state transition, we don't update
		// the conditions LastTransitionTime to Now()
		if cond.Status == status {
			newCondition.LastTransitionTime = cond.LastTransitionTime
		} else {
			log.Info("found status change for LocalCA condition; setting lastTransitionTime", "condition", conditionType, "old_status", cond.Status, "new_status", status, "time", nowTime.Time)
		}

		// Overwrite the existing condition
		localCA.Status.Conditions[idx] = newCondition
		return
	}

	// If we've not found an existing condition of this type, we simply insert
	// the new condition into the slice.
	localCA.Status.Conditions = append(localCA.Status.Conditions, newCondition)
	log.Info("setting lastTransitionTime for LocalCA condition", "condition", conditionType, "time", nowTime.Time)
}

func (r *LocalCAReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&exampleapi.LocalCA{}).
		Complete(r)
}
