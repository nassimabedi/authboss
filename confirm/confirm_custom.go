package confirm

import (
	"context"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"path"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
)

func init() {
	authboss.RegisterModule("confirm-custom", &ConfirmInterceptor{})
}

type ConfirmInterceptor struct {
	origWriter *authboss.Authboss
	ConfirmCus Confirm
	// overridden bool
}

func (i *ConfirmInterceptor) Init(ab *authboss.Authboss) (err error) {
	fmt.Println("---------------------------override------------------------------------Init Confirm----------")

	fmt.Println("-----------------Init---------------------")
	i.origWriter = ab

	// if err = c.Authboss.Config.Core.MailRenderer.Load(EmailConfirmHTML, EmailConfirmTxt); err != nil {
	if err = i.origWriter.Config.Core.MailRenderer.Load(EmailConfirmHTML, EmailConfirmTxt); err != nil {
		// if err = i.ConfirmCus.Authboss.Config.Core.MailRenderer.Load(EmailConfirmHTML, EmailConfirmTxt); err != nil {
		return err
	}

	var callbackMethod func(string, http.Handler)
	methodConfig := i.origWriter.Config.Modules.ConfirmMethod
	if methodConfig == http.MethodGet {
		methodConfig = i.origWriter.Config.Modules.MailRouteMethod
	}
	switch methodConfig {
	case http.MethodGet:
		callbackMethod = i.origWriter.Config.Core.Router.Get
	case http.MethodPost:
		callbackMethod = i.origWriter.Config.Core.Router.Post
	}
	callbackMethod("/confirm", i.origWriter.Config.Core.ErrorHandler.Wrap(i.Get))

	// i.origWriter.Events.Before(authboss.EventAuth, i.ConfirmCus.PreventAuth)
	i.origWriter.Events.After(authboss.EventRegister, i.StartConfirmationWeb)
	// //start
	i.origWriter.Events.AfterCuss(authboss.EventRegister, i.StartConfirmationWebCus)
	// end

	return nil

}

func (i *ConfirmInterceptor) Get(w http.ResponseWriter, r *http.Request) error {
	fmt.Println("---------------------------override------------------------------------Get Confirm----------")
	logger := i.origWriter.RequestLogger(r)

	validator, err := i.origWriter.Config.Core.BodyReader.Read(PageConfirm, r)
	if err != nil {
		return err
	}

	if errs := validator.Validate(); errs != nil {
		logger.Infof("validation failed in Confirm.Get, this typically means a bad token: %+v", errs)
		return i.ConfirmCus.invalidToken(w, r)
	}

	values := authboss.MustHaveConfirmValues(validator)

	//======start =============================
	logger.Infof("===============validator====token=%s===== cus_token:%s==", values.GetToken(), values.GetCustomerToken())
	//=======end =====================================

	rawToken, err := base64.URLEncoding.DecodeString(values.GetToken())
	if err != nil {
		logger.Infof("error decoding token in Confirm.Get, this typically means a bad token: %s %+v", values.GetToken(), err)
		return i.ConfirmCus.invalidToken(w, r)
	}

	if len(rawToken) != confirmTokenSize {
		logger.Infof("invalid confirm token submitted, size was wrong: %d", len(rawToken))
		return i.ConfirmCus.invalidToken(w, r)
	}

	selectorBytes := sha512.Sum512(rawToken[:confirmTokenSplit])
	verifierBytes := sha512.Sum512(rawToken[confirmTokenSplit:])
	selector := base64.StdEncoding.EncodeToString(selectorBytes[:])

	// storer := authboss.EnsureCanConfirm(i.ConfirmCus.Authboss.Config.Storage.Server)
	// tip: This function create in custom file
	storer := authboss.EnsureCanConfirmCus(i.origWriter.Config.Storage.ServerCustom)

	//====================start

	//user, err := storer.LoadByConfirmSelector(r.Context(), selector)
	// fmt.Printf("------------------------customerTokenConfirm:%s--------------", values.GetCustomerToken())
	// user, err := storer.LoadByConfirmSelector(r.Context(), selector, values.GetCustomerToken())
	bb := r.Header.Get("X-Consumer-ID")
	fmt.Printf("------------------------customerTokenConfirm:%s--------------\n", bb)
	user, err := storer.LoadByConfirmSelector(r.Context(), selector, bb)
	//====================End
	if err == authboss.ErrUserNotFound {
		logger.Infof("confirm selector was not found in database: %s", selector)
		return i.ConfirmCus.invalidToken(w, r)
	} else if err != nil {
		return err
	}

	dbVerifierBytes, err := base64.StdEncoding.DecodeString(user.GetConfirmVerifier())
	if err != nil {
		logger.Infof("invalid confirm verifier stored in database: %s", user.GetConfirmVerifier())
		return i.ConfirmCus.invalidToken(w, r)
	}

	if subtle.ConstantTimeEq(int32(len(verifierBytes)), int32(len(dbVerifierBytes))) != 1 ||
		subtle.ConstantTimeCompare(verifierBytes[:], dbVerifierBytes) != 1 {
		logger.Info("stored confirm verifier does not match provided one")
		return i.ConfirmCus.invalidToken(w, r)
	}

	user.PutConfirmSelector("")
	user.PutConfirmVerifier("")
	user.PutConfirmed(true)

	logger.Infof("user %s confirmed their account", user.GetPID())
	if err = i.origWriter.Config.Storage.Server.Save(r.Context(), user); err != nil {
		return err
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		Success:      "You have successfully confirmed your account.",
		RedirectPath: i.origWriter.Config.Paths.ConfirmOK,
	}
	return i.origWriter.Config.Core.Redirector.Redirect(w, r, ro)
}

func (i *ConfirmInterceptor) StartConfirmationWebCus(w http.ResponseWriter, r *http.Request, ro authboss.RedirectOptions, handled bool) (bool, error) {
	//----- Begin : Nassim
	fmt.Println("<<<<<<<<<<<<<<<<<<<<<---override----------StartConfirmationWeb----------------->>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	//----- End : Nassim

	user, err := i.origWriter.CurrentUser(r)
	if err != nil {
		return false, err
	}

	cuser := authboss.MustBeConfirmable(user)
	//start
	//bb := r.Header.Get("customer_token")
	bb := r.Header.Get("X-Consumer-ID")
	if err = i.StartConfirmation(r.Context(), cuser, true, bb); err != nil {
		return false, err
	}
	// if err = c.StartConfirmation(r.Context(), cuser, true); err != nil {
	// 	return false, err
	// }

	//end

	// ro := authboss.RedirectOptions{
	// 	Code:         http.StatusTemporaryRedirect,
	// 	RedirectPath: c.Authboss.Config.Paths.ConfirmNotOK,
	// 	Success:      "Please verify your account, an e-mail has been sent to you.",
	// }

	ro.Code = http.StatusTemporaryRedirect
	ro.RedirectPath = i.origWriter.Config.Paths.ConfirmNotOK
	ro.Success = "Please verify your account, an e-mail has been sent to you."
	// Code: http.StatusTemporaryRedirect,
	// 	RedirectPath: c.Authboss.Config.Paths.ConfirmNotOK,
	// 	Success:      "Please verify your account, an e-mail has been sent to you.",

	return true, i.origWriter.Config.Core.Redirector.Redirect(w, r, ro)
}

func (i *ConfirmInterceptor) StartConfirmationWeb(w http.ResponseWriter, r *http.Request, handled bool) (bool, error) {
	//----- Begin : Nassim
	fmt.Println("<<<<<<<<<<<<<<<<<<<<<-------override------StartConfirmationWeb----------------->>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	//----- End : Nassim

	user, err := i.origWriter.CurrentUser(r)
	if err != nil {
		return false, err
	}

	cuser := authboss.MustBeConfirmable(user)
	//start
	bb := r.Header.Get("X-Consumer-ID")
	if err = i.StartConfirmation(r.Context(), cuser, true, bb); err != nil {
		return false, err
	}
	// if err = c.StartConfirmation(r.Context(), cuser, true); err != nil {
	// 	return false, err
	// }

	//end

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		RedirectPath: i.origWriter.Config.Paths.ConfirmNotOK,
		Success:      "Please verify your account, an e-mail has been sent to you.",
	}
	return true, i.origWriter.Config.Core.Redirector.Redirect(w, r, ro)
}

func (i *ConfirmInterceptor) StartConfirmation(ctx context.Context, user authboss.ConfirmableUser, sendEmail bool, customerToken string) error {
	//----- Begin : Nassim
	fmt.Println("<<<<<<<<<<<|||<<<<<<<<<<------override-------StartConfirmation token----------------->>>>>>>>>>|||>>>>>>>>>>>>>>>>>>")
	//----- End : Nassim

	logger := i.origWriter.Logger(ctx)

	selector, verifier, token, err := GenerateConfirmCreds()
	if err != nil {
		return err
	}

	user.PutConfirmed(false)
	user.PutConfirmSelector(selector)
	user.PutConfirmVerifier(verifier)

	logger.Infof("generated new confirm token for user: %s", user.GetPID())
	if err := i.origWriter.Config.Storage.ServerCustom.Save(ctx, user); err != nil {
		return errors.Wrap(err, "failed to save user during StartConfirmation, user data may be in weird state")
	}

	// logger.Infof(".............start confirmation %s", user.GetCustomerToken())

	// goConfirmEmail(c, ctx, user.GetEmail(), token, user.GetCustomerToken())

	logger.Infof(".............sssstart confirmation %s", customerToken)
	goConfirmEmailCus(i, ctx, user.GetEmail(), token, customerToken)

	return nil
}

var goConfirmEmailCus = func(i *ConfirmInterceptor, ctx context.Context, to, token string, customerToken string) {
	go i.SendConfirmEmail(ctx, to, token, customerToken)
}

func (i *ConfirmInterceptor) SendConfirmEmail(ctx context.Context, to, token string, customerToken string) {
	logger := i.origWriter.Logger(ctx)
	logger.Infof(".............SendConfirmEmail %s", customerToken)
	mailURL := i.mailURL(token, customerToken)

	email := authboss.Email{
		To:       []string{to},
		From:     i.origWriter.Config.Mail.From,
		FromName: i.origWriter.Config.Mail.FromName,
		Subject:  i.origWriter.Config.Mail.SubjectPrefix + "Confirm New Account",
	}

	logger.Infof("sssssending confirm e-mail to: %s", to)
	logger.Infof("-----------------DataConfirmURL........%s ", DataConfirmURL)

	ro := authboss.EmailResponseOptions{
		Data:         authboss.NewHTMLData(DataConfirmURL, mailURL),
		HTMLTemplate: EmailConfirmHTML,
		TextTemplate: EmailConfirmTxt,
	}

	// Here is sending email
	if err := i.origWriter.Email(ctx, email, ro); err != nil {
		logger.Errorf("failed to send confirm e-mail to %s: %+v", to, err)
	}
}

func (i *ConfirmInterceptor) mailURL(token string, customerToken string) string {
	//query := url.Values{FormValueConfirm: []string{token}}
	query := url.Values{FormValueConfirm: []string{token},
		"customer_token": []string{customerToken}}
	fmt.Println("--------------------mailURL...........%s", query)
	fmt.Println("--------------------FormValueConfirm...........%s", FormValueConfirm)
	//queryCusToken :=  url.Values{"customer_token": []string{customerToken}}

	if len(i.origWriter.Config.Mail.RootURL) != 0 {
		return fmt.Sprintf("%s?%s", i.origWriter.Config.Mail.RootURL+"/confirm", query.Encode())
	}

	p := path.Join(i.origWriter.Config.Paths.Mount, "confirm")
	fmt.Println(p)
	fmt.Println(i.origWriter.Config.Paths.RootURL)
	fmt.Println(query.Encode())
	//fmt.Println(customerToken)

	//fmt.Sprintf("%s%s?%s&customer_token=", c.Config.Paths.RootURL, p, query.Encode(), customerToken)
	fmt.Sprintf("%s%s?%s", i.origWriter.Config.Paths.RootURL, p, query.Encode())
	fmt.Println("-----------------------------------------------")

	//return fmt.Sprintf("%s%s?%s&%s", c.Config.Paths.RootURL, p, query.Encode(), queryCusToken.Encode())
	return fmt.Sprintf("%s%s?%s", i.origWriter.Config.Paths.RootURL, p, query.Encode())
}