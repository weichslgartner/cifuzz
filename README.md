<div align="center">
  <img src="/docs/assets/logo.png" alt="Code Intelligence" />
  <h1>cifuzz</h1>
  <p>makes fuzz tests as easy as unit tests</p>
  <a href="https://github.com/CodeIntelligenceTesting/cifuzz/releases">
    <img src="https://img.shields.io/github/v/release/CodeIntelligenceTesting/cifuzz">
  </a>
  <a href="https://github.com/CodeIntelligenceTesting/cifuzz/actions/workflows/pipeline_pr.yml">
    <img src="https://img.shields.io/github/workflow/status/CodeIntelligenceTesting/cifuzz/PR%20Pipeline?logo=github" />
  </a>
  <a href="https://github.com/CodeIntelligenceTesting/cifuzz/blob/main/CONTRIBUTING.md">
    <img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" />
  </a>
  <a href="https://github.com/CodeIntelligenceTesting/cifuzz/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/CodeIntelligenceTesting/cifuzz" />
  </a>

  <br />

  <a href="https://docs.code-intelligence.com/cifuzz-cli" target="_blank">Docs</a>
  |
  <a href="https://github.com/CodeIntelligenceTesting/cifuzz/blob/main/docs/Glossary.md">Glossary</a>
  |
  <a href="https://github.com/CodeIntelligenceTesting/cifuzz/tree/main/examples">Examples</a>
  |
  <a href="https://www.code-intelligence.com/" target="_blank">Website</a>
  |
  <a href="https://www.code-intelligence.com/blog" target="_blank">Blog</a>
  |
  <a href="https://twitter.com/CI_Fuzz" target="_blank">Twitter</a>
  |
  <a href="https://www.youtube.com/channel/UCjXN5ac3tgXgtuCoSnQaEmA" target="_blank">YouTube</a>
</div>

---
> **_IMPORTANT:_** This project is under active development.
Be aware that the behavior of the commands or the configuration
can change.

## What is cifuzz
**cifuzz** is a CLI tool that helps you to integrate and run fuzzing
based tests into your project.

### Features
* Easily setup, create and run fuzz tests 
* Get coverage reports
* Manage your findings with ease
* Integrates into your favorite IDE (see [coverage IDE integrations](docs/Coverage-ide-integrations.md))
* Supports multiple programming languages and build systems

![CLion](/docs/assets/tools/clion.png)
![IDEA](/docs/assets/tools/idea.png)
![VSCode](/docs/assets/tools/vscode.png)
![C++](/docs/assets/tools/cpp.png)
![Java](/docs/assets/tools/java.png)
![CMake](/docs/assets/tools/cmake.png)
![gradle](/docs/assets/tools/gradle.png)
![Maven](/docs/assets/tools/maven.png)

## Getting started
If you are new to the world of fuzzing, we recommend you to take a
look at our [Glossary](docs/Glossary.md) and our 
[example projects](examples/).

> Read the [getting started guide](docs/Getting-Started.md) if you just want to
learn how to fuzz your applications with cifuzz.


## Installation
You can get the latest release [here](https://github.com/CodeIntelligenceTesting/cifuzz/releases/latest)
or by running our install script:

```bash
sh -c "$(curl -fsSL https://raw.githubusercontent.com/CodeIntelligenceTesting/cifuzz/main/install.sh)"
```

If you are using Windows you can download the [latest release](https://github.com/CodeIntelligenceTesting/cifuzz/releases/latest/download/cifuzz_installer_windows.exe) 
and execute it.

By default, cifuzz gets installed in your home directory under `cifuzz`.
You can customize the installation directory with `./cifuzz_installer -i /target/dir`.

Do not forget to add the installation directory to your `PATH`.


### Prerequisites
Depending on our language / build system of choice **cifuzz** has
different prerequisites:

<details>
 <summary>C/C++ (with CMake)</summary>

* [CMake >= 3.16](https://cmake.org/)
* [LLVM >= 11](https://clang.llvm.org/get_started.html)

**Ubuntu / Debian**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
sudo apt install cmake clang llvm
```

**Arch**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
sudo pacman -S cmake clang llvm
```

**macOS**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
brew install cmake llvm
```

**Windows**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
<!-- clang is included in the llvm package --->
At least Visual Studio 2022 version 17 is required.
```bash
choco install cmake llvm
```
</details>

<details>
 <summary>Java with Maven</summary>

* Java JDK >= 8 (e.g. [OpenJDK](https://openjdk.java.net/install/) or
  [Zulu](https://www.azul.com/downloads/zulu-community/))
* [Maven](https://maven.apache.org/install.html)

**Ubuntu / Debian**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
sudo apt install openjdk maven
```

**Arch**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
sudo pacman -S jdk-openjdk maven
```

**macOS**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
brew install openjdk maven
```

**Windows**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
choco install microsoft-openjdk maven
```
</details>

<details>
 <summary>Java with Gradle</summary>

* Java JDK >= 8 (e.g. [OpenJDK](https://openjdk.java.net/install/) or
  [Zulu](https://www.azul.com/downloads/zulu-community/))
* [Gradle](https://gradle.org/install/)

**Ubuntu / Debian**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
sudo apt install openjdk gradle
```

**Arch**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
sudo pacman -S jdk-openjdk gradle
```

**macOS**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
brew install openjdk gradle
```

**Windows**
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
choco install microsoft-openjdk gradle
```
</details>


## Contributing

Want to help improve cifuzz? Check out our [contributing documentation](CONTRIBUTING.md).
There you will find instructions for building the tool locally.

If you find an issue, please report it on the issue tracker.
