module.exports = function (config) {
  config.set({
    basePath: '',
    reporters: ['progress', 'spec', 'coverage'],
    specReporter: {
      maxLogLines: 5,         // nombre de lignes de journalisation par spécification
      suppressErrorSummary: false,  // ne pas afficher le résumé des erreurs
      suppressFailed: false,  // ne pas afficher les spécifications échouées
      suppressPassed: false,  // ne pas afficher les spécifications réussies
      suppressSkipped: false,  // ne pas afficher les spécifications ignorées
      showSpecTiming: false,  // afficher le temps d'exécution de chaque spécification
      failFast: false         // arrêter les tests après la première spécification échouée
    },
    frameworks: ['jasmine', '@angular-devkit/build-angular', 'webpack'],
    plugins: [
      require('karma-jasmine'),
      require('karma-chrome-launcher'),
      require('karma-jasmine-html-reporter'),
      require('karma-coverage'),
      require('@angular-devkit/build-angular/plugins/karma'),
      require('karma-spec-reporter'),
      require('karma-webpack'),
      require('karma-sourcemap-loader')
    ],
    client: {
      clearContext: false // leave Jasmine Spec Runner output visible in browser
    },
    coverageReporter: {
      dir: require('path').join(__dirname, './coverage'),
      subdir: '.',
      reporters: [
        { type: 'html', subdir: './report-html' },
        { type: 'lcov', subdir: './report-lcov' },
        { type: 'lcovonly', subdir: '.', file: 'report-lcovonly.txt' },
        { type: 'text-summary' }
      ]
    },
    port: 9876,
    colors: true,
    logLevel: config.LOG_INFO,
    autoWatch: false,
    browsers: ['HeadlessChrome'],
    browserNoActivityTimeout: 100000,
    browserDisconnectTimeout: 600000,
    customLaunchers: {
      HeadlessChrome: {
        base: 'ChromeHeadless',
        flags: ['--no-sandbox']
      }
    },
    preprocessors: {
      'src/**/*.ts': ['webpack', 'sourcemap']
    },
    webpack: {
      devtool: 'inline-source-map'
    },
    singleRun: false,
    restartOnFileChange: false
  });
};
