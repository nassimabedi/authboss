package authboss

import (
	"context"
	"net/http"

	"fmt"
	//"encoding/json"
)

type contextKey string

// CTX Keys for authboss
const (
	CTXKeyPID  contextKey = "pid"
	CTXKeyUser contextKey = "user"

	CTXKeySessionState contextKey = "session"
	CTXKeyCookieState  contextKey = "cookie"

	// CTXKeyData is a context key for the accumulating
	// map[string]interface{} (authboss.HTMLData) to pass to the
	// renderer
	CTXKeyData contextKey = "data"

	// CTXKeyValues is to pass the data submitted from API request or form
	// along in the context in case modules need it. The only module that needs
	// user information currently is remember so only auth/oauth2 are currently
	// going to use this.
	CTXKeyValues contextKey = "values"
)

func (c contextKey) String() string {
	return "authboss ctx key " + string(c)
}

// CurrentUserID retrieves the current user from the session.
// TODO(aarondl): This method never returns an error, one day we'll change
// the function signature.
func (a *Authboss) CurrentUserID(r *http.Request) (string, error) {
	fmt.Println("......................CurrentUserID...........................")
	if pid := r.Context().Value(CTXKeyPID); pid != nil {
		fmt.Println("..................Hey I'm here :P...........................")
		return pid.(string), nil
	}

	fmt.Println(".................SessionKey=%s...................", SessionKey)
	pid, _ := GetSession(r, SessionKey)
	fmt.Println(".................pid=%s...................", pid)

	fmt.Println(".................SessionKey=%s...................", "customer_token")
	customerToken, _ := GetSession(r, "customer_token")
	fmt.Println(".................pid=%s...................", customerToken)

	return pid, nil
}

// CurrentUserIDP retrieves the current user but panics if it's not available for
// any reason.
func (a *Authboss) CurrentUserIDP(r *http.Request) string {
	i, err := a.CurrentUserID(r)
	if err != nil {
		panic(err)
	} else if len(i) == 0 {
		panic(ErrUserNotFound)
	}

	return i
}

// CurrentUser retrieves the current user from the session and the database.
// Before the user is loaded from the database the context key is checked.
// If the session doesn't have the user ID ErrUserNotFound will be returned.
func (a *Authboss) CurrentUser(r *http.Request) (User, error) {
	fmt.Println("----------------------------CurrentUser--------------------------:**********************")
	contentType := r.Header.Get("Content-type")
	fmt.Println(contentType)
	if err := r.ParseForm(); err != nil {
		fmt.Println("..........eeeeeeeeeeeeeeeeeeeeee...........................")
		return nil, err
	}
	//v := r.Form
	//h := v.Get("name")
	//fmt.Println(h)

	//r.Context()
	//fmt.Println(r.Context().Value("name"))
	////fmt.Fprintf( "Hi there, I love %s!", r.URL.Path[1:])
	////r.ParseForm()
	//if err := r.ParseForm(); err != nil {
	//	fmt.Println("..........eeeeeeeeeeeeeeeeeeeeee...........................")
	//	return nil, err
	//}
	////fmt.Fprintf(w, "Post from website! r.PostFrom = %v\n", r.PostForm)
	//val := r.FormValue("name")
	//fmt.Println(val)
	//
	//===================================
	if user := r.Context().Value(CTXKeyUser); user != nil {
		// fmt.Println(".................I am Here correct :D............user.all:%s.......cusToekn:%s...%s........", CTXKeyUser,
		// 	user.(User),user.(User).GetPID(), user.(User).GetCustomerToken())

		fmt.Println(".................I am Here correct :D............user.all:%s...............", CTXKeyUser,
			user.(User), user.(User).GetPID())
		return user.(User), nil
	}

	pid, err := a.CurrentUserID(r)
	if err != nil {
		return nil, err
	} else if len(pid) == 0 {
		return nil, ErrUserNotFound
	}

	fmt.Println("........I am Here end :D.........pid = %s", pid)
	return a.currentUser(r.Context(), pid)
}

// CurrentUserP retrieves the current user but panics if it's not available for
// any reason.
func (a *Authboss) CurrentUserP(r *http.Request) User {
	i, err := a.CurrentUser(r)
	if err != nil {
		panic(err)
	} else if i == nil {
		panic(ErrUserNotFound)
	}
	return i
}

func (a *Authboss) currentUser(ctx context.Context, pid string) (User, error) {
	//return a.Storage.Server.Load(ctx, pid, customerToken)
	fmt.Println("-----------currentUser-----before save......-------------------------")
	//start
	customerToken := ""
	//end
	//return a.Storage.Server.Load(ctx, pid)
	return a.Storage.Server.Load(ctx, pid, customerToken)
}

// LoadCurrentUserID takes a pointer to a pointer to the request in order to
// change the current method's request pointer itself to the new request that
// contains the new context that has the pid in it.
func (a *Authboss) LoadCurrentUserID(r **http.Request) (string, error) {
	pid, err := a.CurrentUserID(*r)
	if err != nil {
		return "", err
	}

	if len(pid) == 0 {
		return "", nil
	}

	ctx := context.WithValue((**r).Context(), CTXKeyPID, pid)
	*r = (**r).WithContext(ctx)

	return pid, nil
}

// LoadCurrentUserIDP loads the current user id and panics if it's not found
func (a *Authboss) LoadCurrentUserIDP(r **http.Request) string {
	pid, err := a.LoadCurrentUserID(r)
	if err != nil {
		panic(err)
	} else if len(pid) == 0 {
		panic(ErrUserNotFound)
	}

	return pid
}

// LoadCurrentUser takes a pointer to a pointer to the request in order to
// change the current method's request pointer itself to the new request that
// contains the new context that has the user in it. Calls LoadCurrentUserID
// so the primary id is also put in the context.
func (a *Authboss) LoadCurrentUser(r **http.Request) (User, error) {
	fmt.Println("******************LoadCurrentUser********************************")
	if user := (*r).Context().Value(CTXKeyUser); user != nil {
		return user.(User), nil
	}

	pid, err := a.LoadCurrentUserID(r)
	if err != nil {
		return nil, err
	} else if len(pid) == 0 {
		return nil, ErrUserNotFound
	}

	ctx := (**r).Context()
	user, err := a.currentUser(ctx, pid)
	if err != nil {
		return nil, err
	}

	ctx = context.WithValue(ctx, CTXKeyUser, user)
	*r = (**r).WithContext(ctx)
	return user, nil
}

// LoadCurrentUserP does the same as LoadCurrentUser but panics if
// the current user is not found.
func (a *Authboss) LoadCurrentUserP(r **http.Request) User {
	user, err := a.LoadCurrentUser(r)
	if err != nil {
		panic(err)
	} else if user == nil {
		panic(ErrUserNotFound)
	}

	return user
}
