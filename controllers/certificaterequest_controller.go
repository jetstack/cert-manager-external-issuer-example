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
	"fmt"
	"github.com/jetstack/cert-manager-external-issuer-example/pkiutil"

	"github.com/go-logr/logr"
	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	core "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	exampleapi "github.com/jetstack/cert-manager-external-issuer-example/api/v1beta1"
)

// CertificateRequestReconciler reconciles a LocalCA object
type CertificateRequestReconciler struct {
	client.Client
	Log      logr.Logger
	Recorder record.EventRecorder
}

// +kubebuilder:rbac:groups=certmanager.k8s.io,resources=certificaterequests,verbs=get;list;watch;update
// +kubebuilder:rbac:groups=certmanager.k8s.io,resources=certificaterequests/status,verbs=get;update;patch

func (r *CertificateRequestReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("certificaterequest", req.NamespacedName)

	// Fetch the CertificateRequest resource being reconciled
	cr := cmapi.CertificateRequest{}
	if err := r.Client.Get(ctx, req.NamespacedName, &cr); err != nil {
		log.Error(err, "failed to retrieve CertificateRequest resource")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Check the CertificateRequest's issuerRef and if it does not match the
	// exampleapi group name, log a message at a debug level and stop processing.
	if cr.Spec.IssuerRef.Group != exampleapi.GroupVersion.Group {
		log.V(4).Info("resource does not specify an issuerRef group name that we are responsible for", "group", cr.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// If the certificate data is already set then we skip this request as it
	// has already been completed in the past.
	if len(cr.Status.Certificate) > 0 {
		log.V(4).Info("existing certificate data found in status, skipping already completed CertificateRequest")
		return ctrl.Result{}, nil
	}

	// Fetch the LocalCA resource for this request so we can read the CA Secret.
	localCA := exampleapi.LocalCA{}
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: req.Namespace, Name: cr.Spec.IssuerRef.Name}, &localCA); err != nil {
		err := r.setStatus(ctx, log, &cr, cmapi.ConditionFalse, cmapi.CertificateRequestReasonPending,
			"Failed to retrieve LocalCA %s/%s: %v", req.Namespace, cr.Spec.IssuerRef.Name, err)
		return ctrl.Result{}, err
	}

	// Check if the LocalCA resource has been marked Ready
	if !localCAHasCondition(localCA, exampleapi.LocalCACondition{
		Type:   exampleapi.LocalCAConditionReady,
		Status: exampleapi.ConditionTrue,
	}) {
		err := r.setStatus(ctx, log, &cr, cmapi.ConditionFalse, cmapi.CertificateRequestReasonPending,
			"LocalCA %s/%s is not Ready", req.Namespace, cr.Spec.IssuerRef.Name)
		return ctrl.Result{}, err
	}

	// Fetch the Secret resource containing the CA keypair used for signing
	caSecret := core.Secret{}
	if err := r.Client.Get(ctx, client.ObjectKey{Namespace: localCA.Namespace, Name: localCA.Spec.SecretName}, &caSecret); err != nil {
		err := r.setStatus(ctx, log, &cr, cmapi.ConditionFalse, cmapi.CertificateRequestReasonPending,
			"Failed to fetch CA secret resource: %v", err)
		return ctrl.Result{}, err
	}

	// Decode the CA keypair data stored in the Secret
	caPK, caCert, err := decodeCertificateSecret(&caSecret)
	if err != nil {
		log.Error(err, "failed to decode keypair")
		err := r.setStatus(ctx, log, &cr, cmapi.ConditionFalse, cmapi.CertificateRequestReasonPending, "Failed to decode CA secret data: %v", err)
		return ctrl.Result{}, err
	}

	// Generate a 'template' based on the CertificateRequest resource
	template, err := pkiutil.GenerateTemplateFromCertificateRequest(&cr)
	if err != nil {
		log.Error(err, "failed to generate certificate template from request")
		err := r.setStatus(ctx, log, &cr, cmapi.ConditionFalse, cmapi.CertificateRequestReasonFailed, "Failed to generate template for certificate signing: %v", err)
		return ctrl.Result{}, err
	}

	// Sign the template - this is where we actually sign a certificate
	signedPEM, _, err := pkiutil.SignCertificate(template, caCert, template.PublicKey, caPK)
	if err != nil {
		log.Error(err, "failed signing certificate")
		err := r.setStatus(ctx, log, &cr, cmapi.ConditionFalse, cmapi.CertificateRequestReasonFailed, "Failed to sign certificate: %v", err)
		return ctrl.Result{}, err
	}

	// Store the signed certificate data in the status
	cr.Status.Certificate = signedPEM
	// copy the CA data from the CA secret
	cr.Status.CA = caSecret.Data[core.TLSCertKey]

	// Finally, update the status
	return ctrl.Result{}, r.setStatus(ctx, log, &cr, cmapi.ConditionTrue, cmapi.CertificateRequestReasonIssued, "Successfully issued certificate")
}

// localCAHasCondition will return true if the given LocalCA has a
// condition matching the provided LocalCACondition.
// Only the Type and Status field will be used in the comparison, meaning that
// this function will return 'true' even if the Reason, Message and
// LastTransitionTime fields do not match.
func localCAHasCondition(localCA exampleapi.LocalCA, c exampleapi.LocalCACondition) bool {
	existingConditions := localCA.Status.Conditions
	for _, cond := range existingConditions {
		if c.Type == cond.Type && c.Status == cond.Status {
			return true
		}
	}
	return false
}

func (r *CertificateRequestReconciler) setStatus(ctx context.Context, log logr.Logger, cr *cmapi.CertificateRequest, status cmapi.ConditionStatus, reason, message string, args ...interface{}) error {
	// Format the message and update the localCA variable with the new Condition
	completeMessage := fmt.Sprintf(message, args...)
	apiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionReady, status, reason, completeMessage)

	// Fire an Event to additionally inform users of the change
	eventType := core.EventTypeNormal
	if status == cmapi.ConditionFalse {
		eventType = core.EventTypeWarning
	}
	r.Recorder.Event(cr, eventType, reason, completeMessage)
	log.Info(completeMessage)

	// Actually update the LocalCA resource
	// TODO: use the 'status' subresource
	return r.Client.Update(ctx, cr)
}

func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
