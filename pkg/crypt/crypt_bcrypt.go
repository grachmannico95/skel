package crypt

import "golang.org/x/crypto/bcrypt"

func (c *crypto) HashPassword(password string) (hashedPassword string, err error) {
	byteHashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return
	}
	hashedPassword = string(byteHashedPassword)
	return
}

func (c *crypto) CompareHashedPassword(hashedPassword string, password string) (err error) {
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return
	}
	return
}
