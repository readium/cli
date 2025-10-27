package auth

type AuthProvider interface {
	Validate(token string) (string, int, error)
}
