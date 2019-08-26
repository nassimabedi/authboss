package defaults

import (
	"net/http"
	"reflect"
	"strings"
	"time"

	"fmt"
	"html"

	"github.com/dgrijalva/jwt-go"
	"github.com/volatiletech/authboss"
	//	"io/ioutil"
	// "github.com/dgrijalva/jwt-go"
	// abclientstate "github.com/volatiletech/authboss-clientstate"
)

// Responder helps respond to http requests
type Responder struct {
	Renderer authboss.Renderer
}

// NewResponder constructor
func NewResponder(renderer authboss.Renderer) *Responder {
	return &Responder{Renderer: renderer}
}

// Respond to an HTTP request. It's main job is to merge data that comes in from
// various middlewares via the context with the data sent by the controller and
// render that.
func (r *Responder) Respond(w http.ResponseWriter, req *http.Request, code int, page string, data authboss.HTMLData) error {
	ctxData := req.Context().Value(authboss.CTXKeyData)
	if ctxData != nil {
		if data == nil {
			data = authboss.HTMLData{}
		}
		data.Merge(ctxData.(authboss.HTMLData))
	}

	rendered, mime, err := r.Renderer.Render(req.Context(), page, data)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", mime)
	w.WriteHeader(code)

	_, err = w.Write(rendered)
	return err
}

func isAPIRequest(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")
}

// Redirector for http requests
type Redirector struct {
	Renderer authboss.Renderer

	// FormValueName for the redirection
	FormValueName string

	// CoerceRedirectTo200 forces http.StatusTemporaryRedirect and
	// and http.StatusPermanentRedirect to http.StatusOK
	CorceRedirectTo200 bool

	//start
	RenderCus authboss.Authboss
	//end
}

// NewRedirector constructor
func NewRedirector(renderer authboss.Renderer, formValueName string) *Redirector {
	return &Redirector{FormValueName: formValueName, Renderer: renderer}
}

// Redirect the client elsewhere. If it's an API request it will simply render
// a JSON response with information that should help a client to decide what
// to do.
func (r *Redirector) Redirect(w http.ResponseWriter, req *http.Request, ro authboss.RedirectOptions) error {
	var redirectFunction = r.redirectNonAPI
	if isAPIRequest(req) {
		redirectFunction = r.redirectAPI
	}

	return redirectFunction(w, req, ro)
}

type Auth struct {
	*authboss.Authboss
}

func ExampleParse(myToken string, myKey string) {
	token, err := jwt.Parse(myToken, func(token *jwt.Token) (interface{}, error) {
		fmt.Println("--------------------->>>>>>>")
		fmt.Println(token)
		return []byte(myKey), nil
	})

	if err == nil && token.Valid {
		fmt.Println("Your token is valid.  I like your style.")
	} else {
		fmt.Println("This token is terrible!  I cannot accept this.")
	}
}

func (r Redirector) redirectAPI(w http.ResponseWriter, req *http.Request, ro authboss.RedirectOptions) error {

	// =================== start ======================
	cusToken := req.Header.Get("X-Consumer-ID")
	fmt.Printf("------------------------redirectAPI:%s---->>>aaaaaaaaaa.......>>>>----------\n", cusToken)
	// a := UserValues.GetPID()
	// fmt.Println(a)
	// a := authboss.Authboss.user.GetPID()
	// fmt.Println(a)

	// storer_ := authboss.CreatingServerStorerCustom(*authboss.Authboss)
	// storer_ := authboss.CreatingServerStorerCustom()
	// authboss.EnsureCanCreateCus(r.RenderCus)
	// a.Authboss.Storage.Server.Load
	// Auth.CurrentUser(*authboss.Authboss, req)

	// Auth.CurrentUser(req)
	// authboss.EnsureCanCreate(authboss.Authboss)
	// authboss.ServerStorerCustom
	// authboss.CreatingServerStorerCustom
	// r.Authboss.*Config.Storage.Server
	// Auth.Authboss.Config.Storage.Server
	// b := authboss.CreatingServerStorerCustom(*authboss.Authboss)
	// storer_.displayUserInfo(ro.UserEmail, cusToken)

	c := r.Renderer.Load("login")

	if user := req.Context().Value("user"); user != nil {

		fmt.Println(".................I am Here correct :D :D............user.all:%s...............", user)
	}

	fmt.Printf("-------------------formvalueName:%s----------ro:%s------/n", r.FormValueName, c)
	fmt.Printf("-------email1:%s-------------------", ro.UserEmail)

	method := req.URL.Path

	fmt.Printf("------------------------method:%s---->>>url:%s.......>>>>----------/n", req.Method, html.EscapeString(req.URL.Path))

	var jwtKey = []byte("my_secret_key")

	//
	type Claims struct {
		Username string `json:"username"`
		jwt.StandardClaims
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		Username: ro.UserEmail,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		return err
	}

	fmt.Printf("=========tokenString:%s==============/n", tokenString)
	ExampleParse(tokenString, string(jwtKey))

	// ====================== end ======================

	path := ro.RedirectPath
	redir := req.FormValue(r.FormValueName)
	if len(redir) != 0 && ro.FollowRedirParam {
		path = redir
	}

	var status = "success"
	var message string
	if len(ro.Success) != 0 {
		message = ro.Success
	}
	if len(ro.Failure) != 0 {
		status = "failure"
		message = ro.Failure
	}

	data := authboss.HTMLData{
		"location": path,
	}

	//start
	if method == "/register" {

		fmt.Println("==================here===1111===:%s=============>>>>>>>>>", status)
		fmt.Println(ro.FollowRedirParam)
		fmt.Println(authboss.User.GetPID)
		fmt.Println(ro.UserEmail)
		fmt.Println(ro.RedirectPath)
		fmt.Println(ro.Code)
		fmt.Println(ro.FollowRedirParam)
		fmt.Println(ro.Failure)
		if ro.Code == 307 {
			ro.Code = 200
		}
		// pid, ok := authboss.GetSession(req, authboss.SessionKey)
		// fmt.Println(pid)
		// fmt.Println(ok)

	}

	if method == "/login" || method == "/register" && status == "success" {
		data["access_token"] = tokenString
		fmt.Println("---------------------------------------------------------------->>>>>>>")
		// aa := reflect.Indirect(v).FieldByName("Firstname")
		// fmt.Println(reflect.Indirect(v).FieldByName("Firstname"))
		// fmt.Println(reflect.TypeOf(string(aa))
		// fmt.Println(aa.String())
		// fmt.Println(reflect.TypeOf(aa.String()))

		//TODO: error handling
		userInfo, err := r.RenderCus.CurrentUser(req)
		fmt.Println(err)
		fmt.Println(userInfo)
		fmt.Println(userInfo.GetPID)
		t := reflect.TypeOf(userInfo)
		fmt.Println(t)
		v := reflect.ValueOf(userInfo)
		fmt.Println(v)
		userType := reflect.Indirect(v).FieldByName("Type")
		email := reflect.Indirect(v).FieldByName("Email")
		firstname := reflect.Indirect(v).FieldByName("Firstname")
		lastname := reflect.Indirect(v).FieldByName("Lastname")

		nationalCode := reflect.Indirect(v).FieldByName("NationalCode")
		birthday := reflect.Indirect(v).FieldByName("Birthday")
		tenantEmail := reflect.Indirect(v).FieldByName("TenantEmail")
		tenantConfirmURL := reflect.Indirect(v).FieldByName("TenantConfirmURL")
		customFields := reflect.Indirect(v).FieldByName("CustomeFields")
		role := reflect.Indirect(v).FieldByName("Role")
		mobile := reflect.Indirect(v).FieldByName("Mobile")
		mobileSeed := reflect.Indirect(v).FieldByName("MobileSeed")

		fmt.Println("-----------------------------------------------^^^^^^^^^^^^^^^^^^^^^----------------------------------")
		fmt.Println(firstname)
		fmt.Println(reflect.Indirect(v).FieldByName("Lastname"))
		fmt.Println(reflect.Indirect(v).FieldByName("Type"))
		fmt.Println(reflect.Indirect(v).FieldByName("NationalCode"))
		fmt.Println(reflect.Indirect(v).FieldByName("Birthday"))
		fmt.Println(reflect.Indirect(v).FieldByName("TenantEmail"))
		fmt.Println(reflect.Indirect(v).FieldByName("TenantConfirmURL"))
		fmt.Println(reflect.Indirect(v).FieldByName("CustomeFields"))
		fmt.Println(reflect.Indirect(v).FieldByName("Role"))

		data["type"] = userType.String()
		data["email"] = email.String()
		data["tenant_email"] = tenantEmail.String()
		data["tenant_confirm_url"] = tenantConfirmURL.String()

		data["mobile"] = mobile.String()
		data["mobile_seed"] = mobileSeed.String()
		data["firstname"] = firstname.String()
		data["lastname"] = lastname.String()
		data["national_code"] = nationalCode.String()
		data["birthday"] = birthday.String()
		data["role"] = role.String()
		data["custome_fields"] = customFields.String()

		// fmt.Println(reflect.Indirect(v).FieldByName("Lastname"))
		// fmt.Println(reflect.Indirect(v).FieldByName("Type"))
		// fmt.Println(reflect.Indirect(v).FieldByName("NationalCode"))
		// fmt.Println(reflect.Indirect(v).FieldByName("Birthday"))
		// fmt.Println(reflect.Indirect(v).FieldByName("TenantEmail"))
		// fmt.Println(reflect.Indirect(v).FieldByName("TenantConfirmURL"))
		// fmt.Println(reflect.Indirect(v).FieldByName("CustomeFields"))
		// fmt.Println(reflect.Indirect(v).FieldByName("Role"))

		// data["refresh_token"] = ""
		// data["username"] = ro.UserEmail
		// data["fullname"] = ""
		// data["email"] = ro.UserEmail
		// var myslice []string
		// data["roles"] = myslice
		// data["permissions"] = myslice
		// data["email"] =

		// 	"email":"myemail@mail.com",// required when type is "email"
		// "tenant_email": "info@tenant.com" // required when type is "email"
		// "tenant_confirm_url":"tenant.com/tenant" //required
		// "mobile":"09111087815", // required when type is "mobile"
		// "mobile_seed":"+98",
		// "firstname":"firstname",
		// "lastname":"lastname",
		// "national_code":"12907652",
		// "birthday":"1990-04-05",
		// "roles": [],
		// "custome_fields":[{"phone":"887219031":"address":"Tehran"}]
		// "oauth2_provider":"",
		// "oauth2_user_info":[]

		//if status == "307" && method == "/register" {
		//    status = "200"
		//}
	}
	if status == "307" && method == "/register" {
		fmt.Println("===============register status 307")
		status = "200"
	}

	//end

	data["status"] = status
	if len(message) != 0 {
		data["message"] = message
	}

	body, mime, err := r.Renderer.Render(req.Context(), "redirect", data)
	if err != nil {
		return err
	}

	if len(body) != 0 {
		w.Header().Set("Content-Type", mime)
	}

	if ro.Code != 0 {
		//TODO : delete 307
		//if r.CorceRedirectTo200 && (ro.Code == http.StatusTemporaryRedirect || ro.Code == http.StatusPermanentRedirect) {
		if r.CorceRedirectTo200 && (ro.Code == http.StatusTemporaryRedirect || ro.Code == http.StatusPermanentRedirect || ro.Code == 307) {

			w.WriteHeader(http.StatusOK)
		} else {
			fmt.Println("===================================man ro.code hastam :%s====", ro.Code)
			w.WriteHeader(ro.Code)
		}
	}
	_, err = w.Write(body)
	return err
}

func (r Redirector) redirectNonAPI(w http.ResponseWriter, req *http.Request, ro authboss.RedirectOptions) error {
	path := ro.RedirectPath
	redir := req.FormValue(r.FormValueName)
	if len(redir) != 0 && ro.FollowRedirParam {
		path = redir
	}

	if len(ro.Success) != 0 {
		authboss.PutSession(w, authboss.FlashSuccessKey, ro.Success)
	}
	if len(ro.Failure) != 0 {
		authboss.PutSession(w, authboss.FlashErrorKey, ro.Failure)
	}

	http.Redirect(w, req, path, http.StatusFound)
	return nil
}
