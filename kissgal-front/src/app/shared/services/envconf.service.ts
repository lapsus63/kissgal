import { Injectable } from '@angular/core';

export interface EnvConfiguration {
  ENVIRONMENT: string;
  BACKEND_URL: string;
  BACKEND_SUB_PATH: string;
}

interface CustomWindow extends Window {
  // add you custom properties and methods
  dynamicConf: Record<string, unknown>;
}

@Injectable({ providedIn: 'root' })
export class EnvConfigurationService {
  public static loadDynamicConf(): void {
    EnvConfigurationService.configuration = {
      ...EnvConfigurationService.configuration,
      ...(window as CustomWindow & typeof globalThis).dynamicConf
    };
  }

  // This is default configuration, these values are public and can be retreive in production.
  // They are overriden with config.json provided with a k8s configmap. See config.json in .k8s overlays folder
  public static configuration: EnvConfiguration = {
    ENVIRONMENT: 'local',
    BACKEND_URL: 'http://localhost:8080',
    BACKEND_SUB_PATH: '/api/v1'
  };

  public static getEnv(): string {
    return EnvConfigurationService.configuration.ENVIRONMENT;
  }
}

EnvConfigurationService.loadDynamicConf();
