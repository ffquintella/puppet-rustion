# puppet-rustion

## Running tests

Always use `regent` to run the module specs — do not invoke `bundle exec rake spec` or `rspec` directly. The system Ruby is too old for Puppet 8, and `regent` manages its own toolchain.

```
make test
```

Under the hood this runs `regent test . --pattern "spec/{classes,defines}/**/*_spec.rb"` (see `Makefile`). Use `regent build .` for packaging.
