# Contributing

## Building from Source (Linux / macOS)

### Prerequisites
* [git](https://git-scm.com/)
* [make](https://www.gnu.org/software/make/)
* [CMake >= 3.21](https://cmake.org/)
* [LLVM >= 14](https://clang.llvm.org/get_started.html)
* [go >= 1.18](https://go.dev/doc/install)
* [libcap](https://man7.org/linux/man-pages/man3/libcap.3.html)


### Ubuntu / Debian
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
sudo apt install git make cmake clang llvm golang-go libcap-dev
```

### Arch
<!-- when changing this, please make sure it is in sync with the E2E pipeline -->
```bash
sudo pacman -S git make cmake clang llvm go
```
Unfortunately, the Arch `libcap` package does not include the static
libcap library, which is needed to build cifuzz. You have to build it from
source instead:
```bash
pacman -Sy --noconfirm glibc pam linux-api-headers make diffutils
git clone git://git.kernel.org/pub/scm/libs/libcap/libcap.git
cd libcap
git checkout libcap-2.65
make
make install
```

### macOS
<!-- when changing this, please make sure it`is in sync with the E2E pipeline -->
```bash
brew install git cmake llvm go
```

Add the following to your `~/.zshrc` or `~/.bashrc` to use the correct version of
LLVM:
```bash
export PATH=$(brew --prefix)/opt/llvm/bin:$PATH
export LDFLAGS="-L$(brew --prefix)/opt/llvm/lib"
export CPPFLAGS="-I$(brew --prefix)/opt/llvm/include"
```

## Steps
To build **cifuzz** from source you have to execute the following steps:
```bash
git clone https://github.com/CodeIntelligenceTesting/cifuzz.git
cd cifuzz
make test
make install
```
If everything went fine, you will find the newly created directory
`~/cifuzz`. Do not forget to add `~/cifuzz/bin` to your `$PATH`.

To verify the installation we recommend you to start a fuzzing run
in one of our example projects:
``` bash
cd examples/cmake
cifuzz run my_fuzz_test
```
This should stop after a few seconds with an actual finding.
