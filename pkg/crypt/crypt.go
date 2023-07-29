package crypt

type (
	//go:generate mockery --dir pkg/crypt --inpackage --name Crypt --structname CryptMock --outpkg=user --output=pkg/crypt --filename=crypt_mock.go
	Crypt interface {
		HashPassword(password string) (hashedPassword string, err error)
		CompareHashedPassword(hashedPassword string, password string) (err error)
	}
	crypto struct{}
)

func NewCrypt() Crypt {
	return &crypto{}
}
