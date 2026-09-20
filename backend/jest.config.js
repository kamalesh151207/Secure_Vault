module.exports = {
  testEnvironment: 'node',
  coverageDirectory: 'coverage',
  collectCoverageFrom: [
    'src/**/*.js',
    '!src/server.js',
    '!src/lambda.js'
  ],
  testMatch: [
    '**/tests/**/*.test.js'
  ]
};
