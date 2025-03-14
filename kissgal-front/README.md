# KissgalFront

This project was generated using [Angular CLI](https://github.com/angular/angular-cli) version 19.2.1.

## Development server

To start a local development server, run:

```bash
ng serve
```

Once the server is running, open your browser and navigate to `http://localhost:4200/`. The application will automatically reload whenever you modify any of the source files.

## Code scaffolding

Angular CLI includes powerful code scaffolding tools. To generate a new component, run:

```bash
ng generate component component-name
```

For a complete list of available schematics (such as `components`, `directives`, or `pipes`), run:

```bash
ng generate --help
```

## Building

To build the project run:

```bash
ng build
```

This will compile your project and store the build artifacts in the `dist/` directory. By default, the production build optimizes your application for performance and speed.

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

## Running unit tests

To execute unit tests with the [Karma](https://karma-runner.github.io) test runner, use the following command:

```bash
ng test
```

## Running end-to-end tests

For end-to-end (e2e) testing, run:

```bash
ng e2e
```

Angular CLI does not come with an end-to-end testing framework by default. You can choose one that suits your needs.

## Additional Resources

For more information on using the Angular CLI, including detailed command references, visit the [Angular CLI Overview and Command Reference](https://angular.dev/tools/cli) page.


## Links

- [Material Flow Layout](https://m3.material.io/foundations/designing/flow)
- [Angular Material Design](https://material.angular.io/components)
- 
