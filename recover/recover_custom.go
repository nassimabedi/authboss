package recover

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/volatiletech/authboss"
)

func init() {
	authboss.RegisterModule("recover-custom", &RecoverInterceptor{})
}

type RecoverInterceptor struct {
	origWriter *authboss.Authboss
	RecoverCus Recover
	// overridden bool
}

func (i *RecoverInterceptor) Init(ab *authboss.Authboss) (err error) {
	i.origWriter = ab

	if err := i.origWriter.Config.Core.ViewRenderer.Load(PageRecoverStart, PageRecoverEnd); err != nil {
		return err
	}

	if err := i.origWriter.Config.Core.MailRenderer.Load(EmailRecoverHTML, EmailRecoverTxt); err != nil {
		return err
	}

	// i.origWriter.Config.Core.Router.Get("/recover", i.origWriter.Core.ErrorHandler.Wrap(r.StartGet))
	i.origWriter.Config.Core.Router.Post("/recover", i.origWriter.Core.ErrorHandler.Wrap(i.StartPost))
	// i.origWriter.Config.Core.Router.Get("/recover/end", i.origWriter.Core.ErrorHandler.Wrap(r.EndGet))
	// i.origWriter.Config.Core.Router.Post("/recover/end", i.origWriter.Core.ErrorHandler.Wrap(r.EndPost))

	return nil
}

func (i *RecoverInterceptor) StartPost(w http.ResponseWriter, req *http.Request) error {
	fmt.Println("--------------------------override recover--------------------------------------")
	logger := i.origWriter.RequestLogger(req)

	validatable, err := i.origWriter.Core.BodyReader.Read(PageRecoverStart, req)
	if err != nil {
		return err
	}

	if errs := validatable.Validate(); errs != nil {
		logger.Info("recover validation failed")
		data := authboss.HTMLData{authboss.DataValidation: authboss.ErrorMap(errs)}
		return i.origWriter.Core.Responder.Respond(w, req, http.StatusOK, PageRecoverStart, data)
	}

	recoverVals := authboss.MustHaveRecoverStartValues(validatable)

	//start
	fmt.Println("========================================>>>>>>>>>>>>>>>>>>>>>>-----------------1111")
	customerToken := req.Header.Get("X-Consumer-ID")
	fmt.Println(recoverVals.GetPID())
	fmt.Println(recoverVals)

	fmt.Println("========================================>>>>>>>>>>>>>>>>>>>>>>-----------------22222")
	//end

	user, err := i.origWriter.Storage.ServerCustom.Load(req.Context(), recoverVals.GetPID(), customerToken, "email")
	if err == authboss.ErrUserNotFound {
		//TODO: has error when user not found
		fmt.Println("--------------------------error found 11111111--------------------------------------")
		logger.Infof("user %s was attempted to be recovered, user does not exist, faking successful response", recoverVals.GetPID())
		ro := authboss.RedirectOptions{
			Code:         http.StatusTemporaryRedirect,
			RedirectPath: i.origWriter.Config.Paths.RecoverOK,
			Success:      recoverInitiateSuccessFlash,
		}
		return i.origWriter.Core.Redirector.Redirect(w, req, ro)
	}

	ru := authboss.MustBeRecoverable(user)

	selector, verifier, token, err := GenerateRecoverCreds()
	if err != nil {
		return err
	}

	ru.PutRecoverSelector(selector)
	ru.PutRecoverVerifier(verifier)
	ru.PutRecoverExpiry(time.Now().UTC().Add(i.origWriter.Config.Modules.RecoverTokenDuration))

	if err := i.origWriter.Storage.ServerCustom.Save(req.Context(), ru); err != nil {
		return err
	}

	// goRecoverEmail(i.RecoverCus, req.Context(), ru.GetEmail(), token)
	goRecoverEmailCus(i, req.Context(), ru.GetEmail(), token)

	logger.Infof("user %s password recovery initiated", ru.GetPID())
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: i.origWriter.Config.Paths.RecoverOK,
		Success:      recoverInitiateSuccessFlash,
	}
	return i.origWriter.Core.Redirector.Redirect(w, req, ro)
}

var goRecoverEmailCus = func(i *RecoverInterceptor, ctx context.Context, to, encodedToken string) {
	i.SendRecoverEmailCus(ctx, to, encodedToken)
}

// SendRecoverEmail to a specific e-mail address passing along the encodedToken
// in an escaped URL to the templates.
func (i *RecoverInterceptor) SendRecoverEmailCus(ctx context.Context, to, encodedToken string) {
	logger := i.origWriter.Logger(ctx)

	// mailURL := i.RecoverCus.mailURL(encodedToken)
	mailURL := i.mailURL(encodedToken)

	email := authboss.Email{
		To:       []string{to},
		From:     i.origWriter.Config.Mail.From,
		FromName: i.origWriter.Config.Mail.FromName,
		Subject:  i.origWriter.Config.Mail.SubjectPrefix + "Password Reset",
	}

	ro := authboss.EmailResponseOptions{
		HTMLTemplate: EmailRecoverHTML,
		TextTemplate: EmailRecoverTxt,
		Data: authboss.HTMLData{
			DataRecoverURL: mailURL,
		},
	}

	logger.Infof("sending recover e-mail to: %s", to)
	if err := i.origWriter.Email(ctx, email, ro); err != nil {
		logger.Errorf("failed to recover send e-mail to %s: %+v", to, err)
	}
}

func (i *RecoverInterceptor) mailURL(token string) string {
	query := url.Values{FormValueToken: []string{token}}

	if len(i.origWriter.Config.Mail.RootURL) != 0 {
		return fmt.Sprintf("%s?%s", i.origWriter.Config.Mail.RootURL+"/recover/end", query.Encode())
	}

	p := path.Join(i.origWriter.Config.Paths.Mount, "recover/end")
	return fmt.Sprintf("%s%s?%s", i.origWriter.Config.Paths.RootURL, p, query.Encode())
}
