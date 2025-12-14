# In Termux, if you have version.cpp in current directory:

# 1. Create GitHub repo
mkdir sims4-dll && cd sims4-dll
git init

# 2. Copy version.cpp to the repo
# cp /path/to/version.cpp ./
# Or if it's in current directory:
cp version.cpp ./

# 3. Add the file
git add version.cpp

# 4. Create workflow
mkdir -p .github/workflows
cat > .github/workflows/build.yml << 'EOF'
name: Build Windows DLL

on: [push, workflow_dispatch]

jobs:
  build:
    runs-on: windows-2022
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup MSVC
      uses: microsoft/setup-msbuild@v1.1
    
    - name: Download Detours
      run: |
        curl -L -o detours.zip https://github.com/microsoft/Detours/archive/refs/tags/v4.0.1.zip
        tar -xf detours.zip
        cd Detours-4.0.1/src
        nmake
    
    - name: Compile DLL
      shell: cmd
      run: |
        call "C:Program FilesMicrosoft Visual Studio2EnterpriseVCAuxiliaryBuild\u000Bcvars64.bat"
        cl.exe /LD version.cpp /I"Detours-4.0.1include" /link Detours-4.0.1lib.X64detours.lib kernel32.lib user32.lib shell32.lib wininet.lib
    
    - name: Upload DLL
      uses: actions/upload-artifact@v4
      with:
        name: version-dll
        path: version.dll
EOF

# 5. Commit and push
git add .
git commit -m "Add version.cpp and build workflow"
gh repo create sims4-dll --public --source=. --push

# 6. Watch build
gh run watch