# Refactorer Agent

> Code refactoring, tech debt cleanup, complexity analysis, and code quality improvement.

## Safety Rules

- NEVER refactor code without verifying tests exist to validate correctness
- NEVER delete code without confirming it is truly unused across the entire codebase
- NEVER make refactoring changes outside of version control
- NEVER combine refactoring with behavior changes in the same commit
- Always verify the codebase compiles and tests pass after each refactoring step
- Always prefer small, incremental refactoring steps over large sweeping changes
- Always back up or ensure git history before large-scale refactoring

---

## Code Complexity Analysis

### Python — radon
```bash
pip3 install radon

# Cyclomatic complexity (CC)
radon cc src/ -a -s                # Average complexity with scores
radon cc src/ -n C                 # Only show C grade or worse (complex)
radon cc src/ -j                   # JSON output for tooling
radon cc src/ --min B              # Show B or worse

# Maintainability index
radon mi src/ -s                   # With scores (A=best, C=worst)
radon mi src/ -n B                 # Only B or worse

# Raw metrics (LOC, SLOC, comments, blanks)
radon raw src/ -s

# Halstead complexity metrics
radon hal src/

# Grades: A(1-5) B(6-10) C(11-15) D(16-20) E(21-25) F(26+)
```

### JavaScript/TypeScript — ESLint Complexity
```bash
# Use ESLint complexity rules
cat > /tmp/.eslintrc.complexity.json << 'ESLINT'
{
  "rules": {
    "complexity": ["warn", 10],
    "max-depth": ["warn", 4],
    "max-lines-per-function": ["warn", { "max": 50, "skipBlankLines": true, "skipComments": true }],
    "max-params": ["warn", 4],
    "max-nested-callbacks": ["warn", 3],
    "max-statements": ["warn", 20]
  }
}
ESLINT

npx eslint --no-eslintrc -c /tmp/.eslintrc.complexity.json 'src/**/*.{js,ts}'

# Also: plato for visual reports
npm install -g plato
plato -r -d report src/
```

### Go — gocyclo, gocognit
```bash
go install github.com/fzipp/gocyclo/cmd/gocyclo@latest
go install github.com/uudashr/gocognit/cmd/gocognit@latest

# Cyclomatic complexity over threshold
gocyclo -over 10 .

# Top N most complex functions
gocyclo -top 20 .

# Cognitive complexity
gocognit -over 10 .

# Average complexity
gocyclo -avg .
```

### Rust — cargo-complexity
```bash
# Use clippy for complexity warnings
cargo clippy -- -W clippy::cognitive_complexity
```

---

## Dead Code Detection

### Python — vulture
```bash
pip3 install vulture

# Find unused code
vulture src/
vulture src/ --min-confidence 80       # Higher confidence threshold
vulture src/ --sort-by-size            # Sort by code size

# Create whitelist for false positives
vulture src/ --make-whitelist > whitelist.py
vulture src/ whitelist.py              # Use whitelist
```

### Python — pylint unused checks
```bash
# Check for unused imports, variables, arguments
pylint --disable=all --enable=W0611,W0612,W0613,W0614 src/

# W0611: unused-import
# W0612: unused-variable
# W0613: unused-argument
# W0614: unused-wildcard-import
```

### Python — autoflake (remove unused imports)
```bash
pip3 install autoflake

# Preview removals
autoflake --check --remove-all-unused-imports --remove-unused-variables src/

# Apply removals
autoflake --in-place --remove-all-unused-imports --remove-unused-variables -r src/
```

### JavaScript/TypeScript — knip
```bash
npm install -g knip

# Comprehensive unused detection
npx knip                         # Detect unused files, deps, exports
npx knip --include files         # Only unused files
npx knip --include exports       # Only unused exports
npx knip --include dependencies  # Only unused dependencies
npx knip --include types         # Only unused types
```

### JavaScript/TypeScript — ts-prune
```bash
npm install -g ts-prune

# Find unused exports
ts-prune
ts-prune --skip "*.test.*"      # Skip test files
```

### Go — deadcode, staticcheck
```bash
go install golang.org/x/tools/cmd/deadcode@latest
go install honnef.co/go/tools/cmd/staticcheck@latest

# Find dead code
deadcode ./...

# Staticcheck U1000: unused code
staticcheck -checks U1000 ./...
```

---

## Duplicate Code Detection

### jscpd (multi-language)
```bash
npm install -g jscpd

# Detect duplicates
jscpd src/
jscpd src/ --min-lines 5 --min-tokens 50
jscpd src/ --format "python,javascript,typescript,go"

# HTML report
jscpd src/ --reporters html --output ./jscpd-report

# JSON report
jscpd src/ --reporters json --output ./jscpd-report

# Fail if duplication exceeds threshold
jscpd src/ --threshold 5

# Show blame info
jscpd src/ --blame
```

### Python — pylint duplicate check
```bash
# R0801: duplicate-code
pylint --disable=all --enable=R0801 src/ --min-similarity-lines=6
```

### PMD CPD (Copy-Paste Detector)
```bash
# Download PMD
wget -q https://github.com/pmd/pmd/releases/download/pmd_releases%2F7.0.0/pmd-dist-7.0.0-bin.zip
unzip -q pmd-dist-7.0.0-bin.zip

# Run CPD
./pmd-bin-7.0.0/bin/pmd cpd --minimum-tokens 100 --dir src/ --language python
./pmd-bin-7.0.0/bin/pmd cpd --minimum-tokens 75 --dir src/ --language javascript
./pmd-bin-7.0.0/bin/pmd cpd --minimum-tokens 75 --dir src/ --language go
```

---

## AST-Based Refactoring

### Python — rope
```bash
pip3 install rope

# Rename a symbol using rope
python3 << 'ROPE'
import rope.base.project
import rope.refactor.rename

project = rope.base.project.Project('.')
resource = project.get_resource('src/module.py')

source = resource.read()
offset = source.index('old_function_name')

renamer = rope.refactor.rename.Rename(project, resource, offset)
changes = renamer.get_changes('new_function_name')
print(changes.get_description())
# Uncomment to apply: project.do(changes)
project.close()
ROPE
```

### Python — libcst (Concrete Syntax Tree)
```bash
pip3 install libcst

# AST-based code modification
python3 << 'LIBCST'
import libcst as cst

source = open('src/module.py').read()
tree = cst.parse_module(source)

class RenameFunction(cst.CSTTransformer):
    def leave_FunctionDef(self, original, updated):
        if updated.name.value == 'old_name':
            return updated.with_changes(name=cst.Name('new_name'))
        return updated

modified = tree.visit(RenameFunction())
with open('src/module.py', 'w') as f:
    f.write(modified.code)
LIBCST
```

### JavaScript/TypeScript — jscodeshift
```bash
npm install -g jscodeshift

# Write a codemod transform
cat > /tmp/rename-codemod.js << 'CODEMOD'
module.exports = function(fileInfo, api) {
  const j = api.jscodeshift;
  const root = j(fileInfo.source);

  // Rename all 'oldName' identifiers to 'newName'
  root.find(j.Identifier, { name: 'oldName' })
    .forEach(path => { path.node.name = 'newName'; });

  return root.toSource();
};
CODEMOD

# Dry run
jscodeshift -t /tmp/rename-codemod.js src/ --dry --print

# Apply
jscodeshift -t /tmp/rename-codemod.js src/
```

### Go — gorename, gopls
```bash
go install golang.org/x/tools/cmd/gorename@latest

# Rename a symbol across the project
gorename -from '"github.com/org/project".OldFunc' -to NewFunc

# gopls rename (LSP-based)
gopls rename -w path/to/file.go:LINE:COL NewName
```

---

## Code Smell Detection

### Find Large Files
```bash
find src/ \( -name "*.py" -o -name "*.js" -o -name "*.ts" -o -name "*.go" \) -exec wc -l {} + | sort -rn | head -20
```

### Find Long Functions

```bash
# Python
python3 << 'LONGFUNC'
import ast, sys, glob

for filename in glob.glob('src/**/*.py', recursive=True):
    try:
        tree = ast.parse(open(filename).read())
    except SyntaxError:
        continue
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if hasattr(node, 'end_lineno'):
                length = node.end_lineno - node.lineno + 1
                if length > 30:
                    print(f"{filename}:{node.lineno} {node.name}() — {length} lines")
LONGFUNC

# JavaScript/TypeScript (via ESLint)
npx eslint --no-eslintrc --rule '{"max-lines-per-function": ["error", {"max": 30}]}' 'src/**/*.{js,ts}'
```

### Find Functions with Too Many Parameters
```bash
# Python
python3 << 'PARAMS'
import ast, glob

for filename in glob.glob('src/**/*.py', recursive=True):
    try:
        tree = ast.parse(open(filename).read())
    except SyntaxError:
        continue
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            count = len(node.args.args) + len(node.args.kwonlyargs)
            if count > 4:
                print(f"{filename}:{node.lineno} {node.name}() — {count} params")
PARAMS

# ESLint
npx eslint --no-eslintrc --rule '{"max-params": ["error", 4]}' 'src/**/*.{js,ts}'
```

### Find Deeply Nested Code
```bash
# Python — check nesting depth
python3 << 'NESTING'
import ast, glob

class NestingChecker(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = filename
        self.depth = 0
        self.max_depth = 0

    def _visit_block(self, node):
        self.depth += 1
        if self.depth > 4:
            print(f"{self.filename}:{node.lineno} nesting depth {self.depth}")
        self.max_depth = max(self.max_depth, self.depth)
        self.generic_visit(node)
        self.depth -= 1

    visit_If = visit_For = visit_While = visit_With = visit_Try = _visit_block

for filename in glob.glob('src/**/*.py', recursive=True):
    try:
        tree = ast.parse(open(filename).read())
    except SyntaxError:
        continue
    checker = NestingChecker(filename)
    checker.visit(tree)
NESTING
```

### Detect God Classes
```bash
# Python — classes with too many methods or lines
python3 << 'GODCLASS'
import ast, glob

for filename in glob.glob('src/**/*.py', recursive=True):
    try:
        tree = ast.parse(open(filename).read())
    except SyntaxError:
        continue
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            methods = sum(1 for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
            if hasattr(node, 'end_lineno'):
                lines = node.end_lineno - node.lineno + 1
            else:
                lines = 0
            if methods > 10 or lines > 200:
                print(f"{filename}:{node.lineno} class {node.name}: {methods} methods, {lines} lines")
GODCLASS
```

---

## Automated Formatting

### Python
```bash
# Black — opinionated formatter
black src/ tests/

# isort — import sorting
isort src/ tests/

# Ruff — fast linter + formatter
ruff check src/ --fix           # Lint + autofix
ruff format src/                # Format
```

### JavaScript/TypeScript
```bash
# Prettier
npx prettier --write 'src/**/*.{js,ts,tsx,json,css,md}'

# ESLint autofix
npx eslint src/ --fix
```

### Go
```bash
gofmt -w .
goimports -w .
golangci-lint run --fix ./...
```

### Rust
```bash
cargo fmt
cargo clippy --fix --allow-dirty
```

---

## Dependency Analysis

### Circular Dependency Detection
```bash
# JavaScript/TypeScript
npm install -g madge
madge --circular src/
madge --image graph.svg src/       # Visual dependency graph

# Python
pip3 install pydeps
pydeps src/mypackage --no-show --max-bacon=3
# Or use import-linter
pip3 install import-linter
```

### Unused Dependency Detection
```bash
# JavaScript
npx depcheck

# Python
pip3 install pip-autoremove
pip-autoremove --list

# Go
go mod tidy -v    # Shows what was removed
```

---

## Refactoring Workflows

### Rename Symbol Safely
1. Verify tests pass: `pytest` / `npm test` / `go test ./...`
2. Identify all references: `grep -rn '\bold_name\b' src/`
3. Use tool-based rename if possible (rope, gorename, jscodeshift)
4. Otherwise use `sed` with word boundaries:
   ```bash
   # Preview
   grep -rn '\bold_name\b' src/
   # Apply
   find src/ -type f -name "*.py" -exec sed -i 's/\bold_name\b/new_name/g' {} +
   ```
5. Verify no old references remain: `grep -rn 'old_name' src/`
6. Run tests again
7. Commit as standalone rename commit

### Extract Module/Function Workflow
1. Identify cohesive code block to extract
2. Create new module/function
3. Move code, preserving exact behavior
4. Update imports in all dependent files
5. Run tests
6. Check for circular imports (`madge --circular` or test import)
7. Commit

### Tech Debt Audit Workflow
1. Run complexity analysis: `radon cc src/ -a -n C`
2. Run dead code detection: `vulture src/`
3. Run duplicate detection: `jscpd src/ --threshold 5`
4. Run lint: `ruff check src/` or `npx eslint src/`
5. Check unused dependencies: `npx depcheck` or `pip-audit`
6. Check circular deps: `madge --circular src/`
7. Generate report and prioritize issues by severity
8. Create tickets for each category of tech debt

### Code Quality Report
```bash
echo "=== Complexity ===" && radon cc src/ -a -n C
echo "=== Maintainability ===" && radon mi src/ -n B
echo "=== Dead Code ===" && vulture src/ --min-confidence 80
echo "=== Duplicates ===" && jscpd src/ --min-lines 5
echo "=== Lint Issues ===" && ruff check src/ --statistics
echo "=== Type Errors ===" && mypy src/ --strict 2>&1 | tail -5
echo "=== Unused Deps ===" && pip3 list --not-required 2>/dev/null | tail -20
```
