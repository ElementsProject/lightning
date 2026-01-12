module.exports = {

  plugins: [
    {
      rules: {
        'core-lightning': ({ type }) => {
          // Allow standard Core Lightning types
          const standardTypes = [
            // Daemons
            'channeld', 'closingd', 'connectd', 'gossipd', 'hsmd', 'lightningd', 'onchaind',
            'openingd',
            // Related
            'bitcoin', 'cli', 'cln-grpc', 'cln-rpc', 'db', 'wallet', 'wire',
            // Others
            'ci', 'common', 'contrib', 'devtools', 'docs', 'docker', 'github', 'global',
            'meta', 'nit', 'nix', 'release', 'script', 'tests',
          ];

          // Extensions
          const extensions = ['plugin-', 'pyln-', 'tool-']
          if (type) {
            for (const prefix of extensions) {
              if (type.startsWith(prefix)) {
                return [true];
              }
            }
          }

          // Otherwise, must be a standard type
          if (standardTypes.includes(type)) {
            return [true];
          }

          return [
            false,
            `Type must be one of [${standardTypes.join(', ')}] or match patterns [${extensions.join(', ')}]`
          ];
        },
      },
    },
  ],

  rules: {
    // Disable the default type-enum rule since we're using custom validation
    'type-enum': [0],

    // Enable our custom rule
    'core-lightning': [2, 'always'],

    // Keep other standard rules
    'type-case': [2, 'always', 'lower-case'],
    'type-empty': [2, 'never'],
    'subject-empty': [2, 'never'],
    'subject-case': [2, 'never', ['upper-case']],
  },
};
