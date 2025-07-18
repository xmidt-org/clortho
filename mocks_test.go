// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

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

func (m *mockFetcher) ExpectFetchCtx(ctx func(context.Context) bool, location string, prev ContentMeta) *mock.Call {
	return m.On("Fetch", mock.MatchedBy(ctx), location, prev)
}

type mockResolveListener struct {
	mock.Mock
}

func (m *mockResolveListener) OnResolveEvent(event ResolveEvent) {
	m.Called(event)
}

func (m *mockResolveListener) ExpectOnResolveEvent(event ResolveEvent) *mock.Call {
	return m.On("OnResolveEvent", event)
}

type mockRefreshListener struct {
	mock.Mock
}

func (m *mockRefreshListener) OnRefreshEvent(event RefreshEvent) {
	m.Called(event)
}

func (m *mockRefreshListener) ExpectOnRefreshEvent(event RefreshEvent) *mock.Call {
	return m.On("OnRefreshEvent", event)
}
