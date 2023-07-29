// Code generated by mockery v2.29.0. DO NOT EDIT.

package crypt

import mock "github.com/stretchr/testify/mock"

// CryptMock is an autogenerated mock type for the Crypt type
type CryptMock struct {
	mock.Mock
}

// CompareHashedPassword provides a mock function with given fields: hashedPassword, password
func (_m *CryptMock) CompareHashedPassword(hashedPassword string, password string) error {
	ret := _m.Called(hashedPassword, password)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(hashedPassword, password)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// HashPassword provides a mock function with given fields: password
func (_m *CryptMock) HashPassword(password string) (string, error) {
	ret := _m.Called(password)

	var r0 string
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (string, error)); ok {
		return rf(password)
	}
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(password)
	} else {
		r0 = ret.Get(0).(string)
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(password)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

type mockConstructorTestingTNewCryptMock interface {
	mock.TestingT
	Cleanup(func())
}

// NewCryptMock creates a new instance of CryptMock. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewCryptMock(t mockConstructorTestingTNewCryptMock) *CryptMock {
	mock := &CryptMock{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}