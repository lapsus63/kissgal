# KissGal

Showcase your talent to the world: share your works in just a few clicks with your intuitive and accessible online gallery.

## Table of Contents

- [Technical description](#technical-description)
- [Main components](#main-components)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Technical description

A Spring boot / angular web gallery.

## Main components

- Build: Java 21 or higher, maven, node.js and npm
- Run: Keycloak federation

## Project setup

See [README.md](kissgal-back/README.md) from `kissgal-back` and [README.md](kissgal-front/README.md) from `kissgal-front` for each tier details.

## A few words about Authentication

- Generic help to setup a MFA authentication TOTP based in a project: [AUTH.md](AUTH.md)

### Federated authentication using Keycloak

To use Keycloak as an authentication mechanism, here is useful information about the setup :

<!-- cp /opt/dc_keycloak/docker-compose.yml doc/keycloak/ -->
- Example of [docker-compose.yml](doc/keycloak/docker-compose.yml)
- Example of kissgal-front realm configuration [kissgal-front.json](doc/keycloak/kissgal-front.json)
- Log to the Keycloak [admin interface](http://localhost:8083/admin/master/console) (manage realms)
- Log to the Keycloak realm management interface: localhost:8083/realms/<realm-name>/account

External links:

- https://www.keycloak.org/guides#server
- https://www.keycloak.org/getting-started/getting-started-docker
- Angular: https://github.com/mauriciovigolo/keycloak-angular



## Contributing

Please read the [CONTRIBUTING.md](CONTRIBUTING.md) file for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

- **Author**: lapsus63
- **Email**: lapsus63 at gmail dot com
- **GitHub**: [lapsus63](https://github.com/lapsus63)
