# KissgalFront

This project was generated using [Angular CLI](https://github.com/angular/angular-cli).

## Developer notes

Cheat sheet with Angular commands:

```bash
# Start a local development server:
ng serve
# or
npm run start
# Generate a new component:
ng generate component component-name
ng generate --help
# Execute unit tests with Karma:
ng test
ng e2e
# Build the project (compile and store in dist/):
ng build
```

To ensure that your project dependencies are up-to-date and any issues are resolved:

```sh
# lists all installed packages and their dependencies, highlighting any version conflicts.
npm ls
# check the registry to see if any (or, specific) installed packages are currently outdated
npm outdated
# Update all dependencies to their latest versions
npm update (-g ; --save)
# Install missing dependencies and remove unused ones
npm cache clean --force
rm -rf node_modules package-lock.json
npm update @angular/cli @angular/core
npm install
# Audit and fix vulnerabilities
npm audit fix
# Reinstall all dependencies from scratch
rm -rf node_modules package-lock.json
npm install
```

Use nvm to manage node versions:

```sh
# Install nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.38.0/install.sh | bash
# Install node
nvm install 20.17.0
# Use node
nvm list
nvm use 20.17.0
```

Use npm-check to check for outdated, incorrect, and unused dependencies.

```sh
npm install -g npm-check
npm-check (--skip-unused)
```

## Resources and links

- [Flag icons](https://github.com/lipis/flag-icons/tree/main/flags/4x3) - [Google Fonts icons](https://fonts.google.com/icons)
- [Material Flow Layout](https://m3.material.io/foundations/designing/flow)
- [Angular Material Design](https://material.angular.io/components)
