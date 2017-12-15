module.exports = () => {
  return {
    files: ['src/**/*.js', 'public/**/*.*', 'ksm/**/*.*'],
    tests: ['test/**/*.js'],
    env: {
      type: 'node',
      runner: 'node'
    },
    testFramework: 'ava'
  }
}
