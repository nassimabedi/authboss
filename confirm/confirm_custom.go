package confirm

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/smtp"
	"net/url"
	"path"

	"github.com/pkg/errors"
	"github.com/volatiletech/authboss"
	"github.com/volatiletech/authboss/defaults"
)

func init() {
	authboss.RegisterModule("confirm", &ConfirmInterceptor{})
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
	callbackMethod("/confirm_email", i.origWriter.Config.Core.ErrorHandler.Wrap(i.Get))

	callbackMethod("/confirm_sms", i.origWriter.Config.Core.ErrorHandler.Wrap(i.ConfirmSMS))

	// callbackMethod("/send_confirm_email", i.origWriter.Config.Core.ErrorHandler.Wrap(i.SendNewConfirmEmail))

	i.origWriter.Config.Core.Router.Post("/send_confirm_email", i.origWriter.Core.ErrorHandler.Wrap(i.SendNewConfirmEmail))

	// callbackMethod("/confirm_sms", i.origWriter.Config.Core.ErrorHandler.Wrap(i.ConfirmSMS))

	// i.origWriter.Events.Before(authboss.EventAuth, i.ConfirmCus.PreventAuth)
	i.origWriter.Events.After(authboss.EventRegister, i.StartConfirmationWeb)
	// //start
	i.origWriter.Events.AfterCuss(authboss.EventRegister, i.StartConfirmationWebCus)
	// end

	return nil

}

func (i *ConfirmInterceptor) SendNewConfirmEmail(w http.ResponseWriter, req *http.Request) error {
	fmt.Println("------------------override-------SendNewConfirmEmail-------------------------------------")
	logger := i.origWriter.RequestLogger(req)
	validatable, err := i.origWriter.Core.BodyReader.Read("SendNewEmailConfirm", req)
	if err != nil {
		return err
	}
	fmt.Println(validatable)
	fmt.Println(validatable)
	newConfirmVals := authboss.MustHaveNewConfirmEmailValues(validatable)
	fmt.Println(newConfirmVals)
	fmt.Println(newConfirmVals.GetPID())

	customerToken := req.Header.Get("X-Consumer-ID")
	userType := req.Header.Get("user_type")

	user, err := i.origWriter.Storage.ServerCustom.Load(req.Context(), newConfirmVals.GetPID(), customerToken, userType)

	if err == authboss.ErrUserNotFound {
		logger.Infof("user %s was attempted to be recovered, user does not exist, faking successful response", newConfirmVals.GetPID())
		ro := authboss.RedirectOptions{
			Code: http.StatusTemporaryRedirect,
			// RedirectPath: i.origWriter.Authboss.Config.Paths.RecoverOK,
			// Success: recoverInitiateSuccessFlash,
			// Success:      recoverInitiateSuccessFlash,

		}
		return i.origWriter.Core.Redirector.Redirect(w, req, ro)
	}
	fmt.Println(user)

	cuser := authboss.MustBeConfirmable(user)
	bb := req.Header.Get("X-Consumer-ID")

	if err = i.StartConfirmation(req.Context(), cuser, true, bb, userType); err != nil {
		return err
	}

	ro := authboss.RedirectOptions{
		Code: http.StatusTemporaryRedirect,
		// RedirectPath: c.Authboss.Config.Paths.ConfirmNotOK,
		Success: "Please verify your account, an e-mail has been sent to you.",
	}

	ro.Code = http.StatusTemporaryRedirect
	ro.RedirectPath = i.origWriter.Config.Paths.ConfirmNotOK
	ro.Success = "Please verify your account, an e-mail has been sent to you."

	// return i.origWriter.Config.Core.Responder.Respond(w, req, http.StatusOK, PageRegister, data)
	return i.origWriter.Core.Redirector.Redirect(w, req, ro)
	// return true, i.origWriter.Config.Core.Red

}

func (i *ConfirmInterceptor) ConfirmSMS(w http.ResponseWriter, r *http.Request) error {
	logger := i.origWriter.RequestLogger(r)
	logger.Infof("=========================ConfirmSMS================================== ")
	validator, err := i.origWriter.Config.Core.BodyReader.Read(PageConfirm, r)
	if err != nil {
		return err
	}

	if errs := validator.Validate(); errs != nil {
		logger.Infof("validation failed in Confirm.Get, this typically means a bad token: %+v", errs)
		return i.invalidToken(w, r)
	}

	values := authboss.MustHaveConfirmValues(validator)

	//======start =============================
	logger.Infof("===============validator====token=%s===== cus_token:%s==", values.GetToken(), values.GetCustomerToken())
	//=======end =====================================

	rawToken, err := base64.URLEncoding.DecodeString(values.GetToken())
	if err != nil {
		logger.Infof("error decoding token in Confirm.Get, this typically means a bad token: %s %+v", values.GetToken(), err)
		return i.invalidToken(w, r)
	}

	// if len(rawToken) != confirmTokenSize {
	// 	logger.Infof("invalid confirm token submitted, size was wrong: %d", len(rawToken))
	// 	return i.invalidToken(w, r)
	// }

	if len(rawToken) != 12 {
		logger.Infof("invalid confirm token submitted, size was wrong: %d", len(rawToken))
		return i.invalidToken(w, r)
	}

	// selectorBytes := sha512.Sum512(rawToken[:confirmTokenSplit])
	// verifierBytes := sha512.Sum512(rawToken[confirmTokenSplit:])

	selectorBytes := sha512.Sum512(rawToken[:6])
	verifierBytes := sha512.Sum512(rawToken[6:])

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
		// return authboss.Authboss.invalidToken(w, r)
		// return i.ConfirmCus.invalidToken(w, r)
		return i.invalidToken(w, r)
	} else if err != nil {
		return err
	}

	dbVerifierBytes, err := base64.StdEncoding.DecodeString(user.GetConfirmVerifier())
	if err != nil {
		logger.Infof("invalid confirm verifier stored in database: %s", user.GetConfirmVerifier())
		return i.invalidToken(w, r)
	}

	if subtle.ConstantTimeEq(int32(len(verifierBytes)), int32(len(dbVerifierBytes))) != 1 ||
		subtle.ConstantTimeCompare(verifierBytes[:], dbVerifierBytes) != 1 {
		logger.Info("stored confirm verifier does not match provided one")
		return i.invalidToken(w, r)
	}

	user.PutConfirmSelector("")
	user.PutConfirmVerifier("")
	user.PutConfirmed(true)

	logger.Infof("user %s confirmed their account", user.GetPID())
	if err = i.origWriter.Config.Storage.ServerCustom.Save(r.Context(), user); err != nil {
		return err
	}

	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		Success:      "You have successfully confirmed your account.",
		RedirectPath: i.origWriter.Config.Paths.ConfirmOK,
	}
	return i.origWriter.Config.Core.Redirector.Redirect(w, r, ro)

}

func (i *ConfirmInterceptor) invalidToken(w http.ResponseWriter, r *http.Request) error {
	ro := authboss.RedirectOptions{
		Code:         http.StatusTemporaryRedirect,
		Failure:      "confirm token is invalid",
		RedirectPath: i.origWriter.Config.Paths.ConfirmNotOK,
	}
	return i.origWriter.Config.Core.Redirector.Redirect(w, r, ro)
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
		return i.invalidToken(w, r)
	}

	values := authboss.MustHaveConfirmValues(validator)

	//======start =============================
	logger.Infof("===============validator====token=%s===== cus_token:%s==", values.GetToken(), values.GetCustomerToken())
	//=======end =====================================

	rawToken, err := base64.URLEncoding.DecodeString(values.GetToken())
	if err != nil {
		logger.Infof("error decoding token in Confirm.Get, this typically means a bad token: %s %+v", values.GetToken(), err)
		return i.invalidToken(w, r)
	}

	if len(rawToken) != confirmTokenSize {
		logger.Infof("invalid confirm token submitted, size was wrong: %d", len(rawToken))
		return i.invalidToken(w, r)
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
		// return authboss.Authboss.invalidToken(w, r)
		// return i.ConfirmCus.invalidToken(w, r)
		return i.invalidToken(w, r)
	} else if err != nil {
		return err
	}

	dbVerifierBytes, err := base64.StdEncoding.DecodeString(user.GetConfirmVerifier())
	if err != nil {
		logger.Infof("invalid confirm verifier stored in database: %s", user.GetConfirmVerifier())
		return i.invalidToken(w, r)
	}

	if subtle.ConstantTimeEq(int32(len(verifierBytes)), int32(len(dbVerifierBytes))) != 1 ||
		subtle.ConstantTimeCompare(verifierBytes[:], dbVerifierBytes) != 1 {
		logger.Info("stored confirm verifier does not match provided one")
		return i.invalidToken(w, r)
	}

	user.PutConfirmSelector("")
	user.PutConfirmVerifier("")
	user.PutConfirmed(true)

	logger.Infof("user %s confirmed their account", user.GetPID())
	if err = i.origWriter.Config.Storage.ServerCustom.Save(r.Context(), user); err != nil {
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
	fmt.Println("<<<<<<<<<<<<<<<<<<<<<---override----------StartConfirmationWebCus----------------->>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	//----- End : Nassim

	user, err := i.origWriter.CurrentUser(r)
	if err != nil {
		return false, err
	}

	cuser := authboss.MustBeConfirmable(user)
	//start
	//bb := r.Header.Get("customer_token")
	bb := r.Header.Get("X-Consumer-ID")
	userType := r.Header.Get("user_type")
	if err = i.StartConfirmation(r.Context(), cuser, true, bb, userType); err != nil {
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
	user_type := r.Header.Get("user_type")
	if err = i.StartConfirmation(r.Context(), cuser, true, bb, user_type); err != nil {
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

func GenerateConfirmCredsCus(userType string) (selector, verifier, token string, err error) {
	fmt.Println("--------------GenerateConfirmCreds----------------------")
	fmt.Println(userType)

	fmt.Println(selector)
	fmt.Println(confirmTokenSize)

	var rawToken []byte
	// var selectorBytes []byte
	// var verifierBytes []byte
	var selectorBytes [64]byte
	var verifierBytes [64]byte

	if userType == "email" {
		rawToken = make([]byte, confirmTokenSize)
	} else if userType == "mobile" {
		rawToken = make([]byte, 12)
	}

	if _, err = io.ReadFull(rand.Reader, rawToken); err != nil {
		return "", "", "", err
	}

	if userType == "email" {
		selectorBytes = sha512.Sum512(rawToken[:confirmTokenSplit])
		verifierBytes = sha512.Sum512(rawToken[confirmTokenSplit:])
	} else if userType == "mobile" {
		selectorBytes = sha512.Sum512(rawToken[:6])
		verifierBytes = sha512.Sum512(rawToken[6:])
	}

	fmt.Println(rawToken)
	fmt.Println(confirmTokenSplit)
	fmt.Println(verifierBytes)
	fmt.Println(selectorBytes)
	fmt.Println("*********************************************")

	return base64.StdEncoding.EncodeToString(selectorBytes[:]),
		base64.StdEncoding.EncodeToString(verifierBytes[:]),
		base64.URLEncoding.EncodeToString(rawToken),
		nil
}

func (i *ConfirmInterceptor) StartConfirmation(ctx context.Context, user authboss.ConfirmableUser, sendEmail bool, customerToken string, userType string) error {
	//----- Begin : Nassim
	fmt.Println("<<<<<<<<<<<|||<<<<<<<<<<------override-------StartConfirmation token----------------->>>>>>>>>>|||>>>>>>>>>>>>>>>>>>")
	//----- End : Nassim

	logger := i.origWriter.Logger(ctx)

	selector, verifier, token, err := GenerateConfirmCredsCus(userType)
	if err != nil {
		return err
	}

	fmt.Println(token)
	fmt.Println("------------------------------------->>>>>>>>>>>>>>>>>>>>>>>>>>....................")

	arbitraryField := user.GetArbitrary()
	fmt.Println(arbitraryField["firstname"])
	fmt.Println(arbitraryField["tenant_email"])
	fmt.Println(arbitraryField["tenant_confirm_url"])
	fmt.Println(arbitraryField["type"])

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
	goConfirmEmailCus(i, ctx, user.GetEmail(), token, customerToken, arbitraryField["type"], arbitraryField["tenant_email"], arbitraryField["tenant_confirm_url"], arbitraryField["mobile"])

	return nil
}

var goConfirmEmailCus = func(i *ConfirmInterceptor, ctx context.Context, to, token string, customerToken string, user_type string, tenant_email string, tenant_confirm_url string, mobile string) {
	go i.SendConfirmEmail(ctx, to, token, customerToken, user_type, tenant_email, tenant_confirm_url, mobile)
}

type unencryptedAuth struct {
	smtp.Auth
}

func (a unencryptedAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	s := *server
	s.TLS = true
	return a.Auth.Start(&s)
}

func (i *ConfirmInterceptor) SendConfirmEmail(ctx context.Context, to, token string, customerToken string, user_type string, tenant_email string, tenant_confirm_url string, mobile string) {
	logger := i.origWriter.Logger(ctx)
	logger.Infof(".............SendConfirmEmail %s", customerToken)
	logger.Infof("--------------tenant_confirm_url: %s", tenant_confirm_url)
	logger.Infof("--------------token: %s", token)
	emailBody := creatEmailBody(token, tenant_confirm_url)

	//TODO : 1.delete customerToken 2. added send sms
	if len(tenant_email) > 0 && user_type == "email" {
		//if len(tenant_email) > 0  {
		// i.sendEmailByConsumer(ctx, to, token, customerToken, tenant_email, emailBody)
		i.sendEmailByManam(to, customerToken, emailBody, tenant_email)
	} else if len(tenant_email) == 0 && user_type == "email" {
		i.sendEmailByManam(to, customerToken, emailBody, "")
	} else if user_type == "mobile" {
		smsBody := creatSMSBody(token, tenant_confirm_url)
		i.sendSMSByManam(mobile, customerToken, smsBody)
	}

	// email := authboss.Email{
	// 	To:       []string{to},
	// 	From:     i.origWriter.Config.Mail.From,
	// 	FromName: i.origWriter.Config.Mail.FromName,
	// 	Subject:  i.origWriter.Config.Mail.SubjectPrefix + "Confirm New Account",
	// }

	// mailURL := i.mailURL(token, customerToken)
	// logger.Infof(".............mailURL:  %s", mailURL)

	// logger.Infof("sssssending confirm e-mail to: %s", to)
	// logger.Infof("-----------------DataConfirmURL........%s ", DataConfirmURL)

	// ro := authboss.EmailResponseOptions{
	// 	Data:         authboss.NewHTMLData(DataConfirmURL, mailURL),
	// 	HTMLTemplate: EmailConfirmHTML,
	// 	TextTemplate: EmailConfirmTxt,
	// }

	// // Here is sending email
	// if err := i.origWriter.Email(ctx, email, ro); err != nil {
	// 	logger.Infof("-----------------------Error sending email ---------------------------------")
	// 	logger.Errorf("failed to send confirm e-mail to %s: %+v", to, err)
	// }

	// //end
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

//start

func (i *ConfirmInterceptor) sendEmailByConsumer(ctx context.Context, to, token string, customerToken string, tenant_email string, emailBody string) error {
	mailURL := i.mailURL(token, customerToken)

	fmt.Println(".............mailURL:  %s", mailURL)

	email := authboss.Email{
		To: []string{to},
		// From:     i.origWriter.Config.Mail.From,
		From:     tenant_email,
		FromName: i.origWriter.Config.Mail.FromName,
		Subject:  i.origWriter.Config.Mail.SubjectPrefix + "Confirm New Account",
	}

	fmt.Println("sssssending confirm e-mail to: %s", to)
	fmt.Println("-----------------DataConfirmURL........%s ", DataConfirmURL)

	//TODO: create body
	fmt.Println(emailBody)
	ro := authboss.EmailResponseOptions{
		Data:         authboss.NewHTMLData(DataConfirmURL, mailURL),
		HTMLTemplate: EmailConfirmHTML,
		TextTemplate: EmailConfirmTxt,
	}

	// Here is sending email
	if err := i.origWriter.Email(ctx, email, ro); err != nil {
		fmt.Println("-----------------------Error sending email ---------------------------------")
		fmt.Println("failed to send confirm e-mail to %s: %+v", to, err)
		return err
	}
	return nil

}

func (i *ConfirmInterceptor) sendEmailByManam(to, customerToken string, emailBody string, from string) error {

	server := fmt.Sprintf("%s:%d", "smtp.manam.ir", 587)
	auth := unencryptedAuth{
		smtp.PlainAuth(
			"",
			"confirm@manam.ir",
			// "info@google.com",
			"Conf1010",
			"smtp.manam.ir",
		),
	}

	mailer := defaults.NewSMTPMailer(server, auth)

	if len(from) == 0 {
		from = i.origWriter.Config.Mail.From
	}

	fmt.Println("-----------------------sendEmailByManam ---------------------------------", from)
	mail := authboss.Email{
		// From:    creds.Email,
		// To:      []string{creds.Email},

		// From:    "confirm@manam.ir", //i.origWriter.Config.Mail.From
		// To:      []string{"nassimabedi@gmail.com"},
		// Subject: "Authboss Test SMTP Mailer1111", //i.origWriter.Config.Mail.SubjectPrefix + "Confirm New Account"

		// From:    i.origWriter.Config.Mail.From,
		From: from,
		To:   []string{to},
		// Subject: i.origWriter.Config.Mail.SubjectPrefix + "Confirm New Account",
		// Subject: i.origWriter.Config.Mail.SubjectPrefix + " in Manam",
	}

	txtOnly := mail
	// txtOnly.Subject += ": Text Content"
	// txtOnly.Subject += i.origWriter.Config.Mail.SubjectPrefix + "Confirm New Account"
	txtOnly.Subject += i.origWriter.Config.Mail.SubjectPrefix + " in Manam"
	// txtOnly.TextBody = "Authboss\nSMTP\nTest\nWith\nNewlines"
	txtOnly.TextBody = emailBody
	// txtOnly.From = from
	// txtOnly.FromName = from

	if err_ := mailer.Send(context.Background(), txtOnly); err_ != nil {
		//t.Error(err)
		fmt.Println("---------------------error for sending email-----------------------")
		fmt.Println(err_)
	}

	return nil

}

func (i *ConfirmInterceptor) sendSMSByManam(mobile, customerToken string, body string) error {

	fmt.Println("-------------------------------send SMS By Manam---------------------")
	fmt.Println("------------------------------- mobile : %s ---------------------", mobile)
	fmt.Println("------------------------------- body: %s ---------------------", body)

	SendSMS("09123599895", "e4h31", mobile, "50001060669766", body, false)

	return nil

}

func creatEmailBody(token string, tenant_confirm_url string) string {
	// Please copy and paste the following link into your browser to confirm your account\n\nhttp://localhost:3000/auth/confirm?cnf=x5kaCnV_G-b43oXlm3OJ98QBhWuBvwpEFvJ6WJWBWq8ssj13wrHATssafmQl-sadRNmvfnFVH9PT-www8Od1bg%3D%3D&amp;customer_token=kiss_customerooooosdsd4
	htmlbody := "Hi <br>"
	htmlbody += "Please copy and paste the following link into your browser to confirm your account\n\n"
	if len(tenant_confirm_url) > 0 {
		htmlbody += tenant_confirm_url + "?cnf=" + token
	} else {
		htmlbody += token
	}

	htmlbody += "\n\n Email From Manam"

	return htmlbody
}

func creatSMSBody(token string, tenant_confirm_url string) string {
	// Please copy and paste the following link into your browser to confirm your account\n\nhttp://localhost:3000/auth/confirm?cnf=x5kaCnV_G-b43oXlm3OJ98QBhWuBvwpEFvJ6WJWBWq8ssj13wrHATssafmQl-sadRNmvfnFVH9PT-www8Od1bg%3D%3D&amp;customer_token=kiss_customerooooosdsd4
	htmlbody := "Hi \n \n"
	htmlbody += "Please copy and paste the following code in your site to confirm your account\n\n"
	htmlbody += token
	htmlbody += "\n Here is The address:"
	htmlbody += tenant_confirm_url
	htmlbody += "\n From Manam"
	return htmlbody
}

//end
