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

type mockFetcher struct {
	mock.Mock
}

func (m *mockFetcher) Fetch(ctx context.Context, location string, prev ContentMeta) ([]Key, ContentMeta, error) {
	args := m.Called(ctx, location, prev)
	return args.Get(0).([]Key),
		args.Get(1).(ContentMeta),
		args.Error(2)
}

func (m *mockFetcher) ExpectFetch(ctx context.Context, location string, prev ContentMeta) *mock.Call {
	return m.On("Fetch", ctx, location, prev)
}

type mockKeyRing struct {
	mock.Mock
}

func (m *mockKeyRing) Get(kid string) (Key, bool) {
	args := m.Called(kid)
	return args.Get(0).(Key), args.Bool(1)
}

func (m *mockKeyRing) Len() int {
	return m.Called().Int(0)
}

func (m *mockKeyRing) OnRefreshEvent(event RefreshEvent) {
	m.Called(event)
}

func (m *mockKeyRing) ExpectOnRefreshEvent(event RefreshEvent) *mock.Call {
	return m.On("OnRefreshEvent", event)
}

func (m *mockKeyRing) OnResolveEvent(event ResolveEvent) {
	m.Called(event)
}

func (m *mockKeyRing) ExpectOnResolveEvent(event ResolveEvent) *mock.Call {
	return m.On("OnResolveEvent", event)
}

func (m *mockKeyRing) Add(keys ...Key) int {
	actual := make([]interface{}, 0, len(keys))
	for _, k := range keys {
		actual = append(actual, k)
	}

	args := m.Called(actual...)
	return args.Int(0)
}

func (m *mockKeyRing) ExpectAdd(keys ...Key) *mock.Call {
	expect := make([]interface{}, 0, len(keys))
	for _, k := range keys {
		expect = append(expect, k)
	}

	return m.On("Add", expect...)
}
