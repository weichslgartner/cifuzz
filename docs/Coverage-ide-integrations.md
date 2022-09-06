# Coverage IDE integrations

## CLion
You can start coverage runs from within CLion with the help of CMake
user presets. Custom cifuzz presets can be added by running:
    
    cifuzz integrate cmake

Those presets have to be enabled before they show up as a run
configuration.
See [here](https://www.jetbrains.com/help/clion/cmake-presets.html#detect)
for more details.
![fuzz test in CMake](/docs/assets/coverage_clion.gif)

## VS Code
You can start coverage runs from within VS Code with the help of tasks.
See [here](https://code.visualstudio.com/docs/editor/tasks) for more
details. A custom cifuzz coverage task can be added by running:

    cifuzz integrate vscode

Coverage reports can be visualized with the
[Coverage Gutters extension](https://marketplace.visualstudio.com/items?itemName=ryanluker.vscode-coverage-gutters).
![fuzz test in CMake](/docs/assets/coverage_vscode.gif)
