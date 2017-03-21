# Cartrabbit Validator for Herbert

Add the below piece of code in **cartrabbit.config.php** to load Cartrabbit Validation service provider

`'providers' => array(`

 `       Cartrabbit\Validator\ValidationServiceProvider::class`

 `       )`
 
 # Cartrabbit Validator Example 
 
**Validate single data**
 
`$data = \Cartrabbit\Validator\Facades\Validator::single($data, ['num', 'min:3'])`

**Validate multiple data**
 
`$data = \Cartrabbit\Validator\Facades\Validator::multiple($data, [
    'field-name' => ['alnum', 'min:5'],
    'email'      => ['email'],
    'age'        => ['num']
]);`

returns empty value for the key failed else the value as send.
