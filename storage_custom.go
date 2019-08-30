package authboss

import (
	"context"
)

type ConfirmingServerStorerCustom interface {
	ServerStorerCustom

	// LoadByConfirmSelector finds a user by his confirm selector field
	// and should return ErrUserNotFound if that user cannot be found.
	LoadByConfirmSelector(ctx context.Context, selector string, customerToken string) (ConfirmableUser, error)
}

type ServerStorerCustom interface {
	// Load will look up the user based on the passed the PrimaryID
	//start
	// Load(ctx context.Context, key string, customerToken string) (User, error)
	Load(ctx context.Context, key string, customerToken string, userType string) (User, error)
	//Load(ctx context.Context, key string) (User, error)
	//end

	// Save persists the user in the database, this should never
	// create a user and instead return ErrUserNotFound if the user
	// does not exist.
	Save(ctx context.Context, user User) error
}

// type CreatingServerViewUserStorerCustom interface {
// 	ServerStorerCustom

// 	Save(ctx context.Context, user User) error
// 	displayUserInfo(ctx context.Context, pid string, customerToken string) (ConfirmableUser, error)
// }

type CreatingServerStorerCustom interface {
	ServerStorerCustom

	// New creates a blank user, it is not yet persisted in the database
	// but is just for storing data
	New(ctx context.Context) User
	// Create the user in storage, it should not overwrite a user
	// and should return ErrUserFound if it currently exists.
	Create(ctx context.Context, user User) error

	//start
	// displayUserInfo(ctx context.Context, pid string, customerToken string) (ConfirmableUser, error)
	//end
}

// RecoveringServerStorer allows users to be recovered by a token
type RecoveringServerStorerCustom interface {
	ServerStorerCustom

	// LoadByRecoverSelector finds a user by his recover selector field
	// and should return ErrUserNotFound if that user cannot be found.
	// TODO: must add customerToken
	LoadByRecoverSelector(ctx context.Context, selector string, customerToken string) (RecoverableUser, error)
}

type RememberingServerStorerCustom interface {
	ServerStorerCustom

	// AddRememberToken to a user
	AddRememberToken(ctx context.Context, pid, token string) error
	// DelRememberTokens removes all tokens for the given pid
	DelRememberTokens(ctx context.Context, pid string) error
	// UseRememberToken finds the pid-token pair and deletes it.
	// If the token could not be found return ErrTokenNotFound
	UseRememberToken(ctx context.Context, pid, token string) error
}

type InterceptorStorage struct {
	ConfirmingServerStorerCustom ConfirmingServerStorer
	ServerStorerCustom           ServerStorer
	CreatingServerStorerCustom   CreatingServerStorer
	RecoveringServerStorerCustom RecoveringServerStorer
	// CreatingServerViewUserStorerCustom CreatingServerViewUserStorerCustom
	// overridden bool
}

func EnsureCanConfirmCus(storer ServerStorerCustom) ConfirmingServerStorerCustom {
	s, ok := storer.(ConfirmingServerStorerCustom)
	if !ok {
		panic("could not upgrade ServerStorer to ConfirmingServerStorer, check your struct")
	}

	return s
}

func EnsureCanCreateCus(storer ServerStorerCustom) CreatingServerStorerCustom {
	s, ok := storer.(CreatingServerStorerCustom)
	if !ok {
		panic("could not upgrade ServerStorer to CreatingServerStorer, check your struct")
	}

	return s
}

func EnsureCanRecoverCus(storer ServerStorerCustom) RecoveringServerStorerCustom {
	s, ok := storer.(RecoveringServerStorerCustom)
	if !ok {
		panic("could not upgrade ServerStorer to CreatingServerStorer, check your struct")
	}

	return s
}

// func EnsureCanRegisterCus(storer ServerStorerCustom) CreatingServerViewUserStorerCustom {
// 	s, ok := storer.(CreatingServerViewUserStorerCustom)
// 	if !ok {
// 		panic("could not upgrade ServerStorer to ConfirmingServerStorer, check your struct")
// 	}

// 	return s
// }
