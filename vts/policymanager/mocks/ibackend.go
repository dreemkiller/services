// Code generated by MockGen. DO NOT EDIT.
// Source: ../../policy/ibackend.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	viper "github.com/spf13/viper"
)

// MockIBackend is a mock of IBackend interface.
type MockIBackend struct {
	ctrl     *gomock.Controller
	recorder *MockIBackendMockRecorder
}

// MockIBackendMockRecorder is the mock recorder for MockIBackend.
type MockIBackendMockRecorder struct {
	mock *MockIBackend
}

// NewMockIBackend creates a new mock instance.
func NewMockIBackend(ctrl *gomock.Controller) *MockIBackend {
	mock := &MockIBackend{ctrl: ctrl}
	mock.recorder = &MockIBackendMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockIBackend) EXPECT() *MockIBackendMockRecorder {
	return m.recorder
}

// Close mocks base method.
func (m *MockIBackend) Close() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Close")
}

// Close indicates an expected call of Close.
func (mr *MockIBackendMockRecorder) Close() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Close", reflect.TypeOf((*MockIBackend)(nil).Close))
}

// Evaluate mocks base method.
func (m *MockIBackend) Evaluate(ctx context.Context, policy string, result, evidence map[string]interface{}, endorsements []string) (map[string]interface{}, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Evaluate", ctx, policy, result, evidence, endorsements)
	ret0, _ := ret[0].(map[string]interface{})
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Evaluate indicates an expected call of Evaluate.
func (mr *MockIBackendMockRecorder) Evaluate(ctx, policy, result, evidence, endorsements interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Evaluate", reflect.TypeOf((*MockIBackend)(nil).Evaluate), ctx, policy, result, evidence, endorsements)
}

// GetName mocks base method.
func (m *MockIBackend) GetName() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetName")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetName indicates an expected call of GetName.
func (mr *MockIBackendMockRecorder) GetName() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetName", reflect.TypeOf((*MockIBackend)(nil).GetName))
}

// Init mocks base method.
func (m *MockIBackend) Init(v *viper.Viper) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Init", v)
	ret0, _ := ret[0].(error)
	return ret0
}

// Init indicates an expected call of Init.
func (mr *MockIBackendMockRecorder) Init(v interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Init", reflect.TypeOf((*MockIBackend)(nil).Init), v)
}
