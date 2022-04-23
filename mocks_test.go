package clortho

import (
	"context"

	"github.com/stretchr/testify/mock"
)

type mockLoader struct {
	mock.Mock
}

func (m *mockLoader) LoadContent(ctx context.Context, location string, meta ContentMeta) ([]byte, ContentMeta, error) {
	args := m.Called(ctx, location, meta)
	return args.Get(0).([]byte),
		args.Get(1).(ContentMeta),
		args.Error(2)
}

func (m *mockLoader) ExpectLoadContent(ctx context.Context, location string, meta ContentMeta) *mock.Call {
	return m.On("LoadContent", ctx, location, meta)
}

type mockParser struct {
	mock.Mock
}

func (m *mockParser) Parse(format string, data []byte) ([]Key, error) {
	args := m.Called(format, data)
	return args.Get(0).([]Key),
		args.Error(1)
}

func (m *mockParser) ExpectParse(format string, data []byte) *mock.Call {
	return m.On("Parse", format, data)
}
