package mocks

import "github.com/stretchr/testify/mock"

type RunfilesFinderMock struct {
	mock.Mock
}

func (m *RunfilesFinderMock) CIFuzzIncludePath() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *RunfilesFinderMock) ClangPath() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *RunfilesFinderMock) CMakePath() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *RunfilesFinderMock) CMakePresetsPath() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *RunfilesFinderMock) JazzerAgentDeployJarPath() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *RunfilesFinderMock) JazzerDriverPath() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *RunfilesFinderMock) LibMinijailPreloadPath() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *RunfilesFinderMock) LLVMCovPath() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *RunfilesFinderMock) LLVMProfDataPath() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *RunfilesFinderMock) LLVMSymbolizerPath() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *RunfilesFinderMock) Minijail0Path() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *RunfilesFinderMock) ProcessWrapperPath() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *RunfilesFinderMock) ReplayerSourcePath() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *RunfilesFinderMock) VSCodeTasksPath() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}
