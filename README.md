<img src="https://www.activeledger.io/wp-content/uploads/2018/09/Asset-23.png" alt="Activeledger" width="500"/>

# Activeledger - PHP SDK

The Activeledger PHP SDK has been build to provide an easy way to connect your php web application to an Activeledger Network

### Activeledger

[Visit Activeledger.io](https://activeledger.io/)

[Read Activeledgers documentation](https://github.com/activeledger/activeledger)

## Installation

```
$ composer require activeledger/sdk ~0.0.1
$ composer install -o
```

## Usage

The SDK currently supports the following functionality

- Connection handling
- Key generation
- Key onboarding
- Transaction building
- Encrypted & unencrypted transaction posting

Once the SDK has been installed import the classes with the autoloader

```php
require __DIR__ . '/vendor/autoload.php';
```

### Connection

When sending a transaction, you must pass a connection that provides the information needed to establish a link to the network and specified node.

To do this a connection object must be created. This object must be passed the protocol, address, port, and the encryption flag.

#### Example

```php
require __DIR__ . '/vendor/autoload.php';

// Setup the connection object to use localhost over http unencrypted
$connection = new activeledger\sdk\Connection("http", "127.0.0.1", 5260, false);

// Use localhost but encrypt transactions
$connection = new activeledger\sdk\Connection("http", "127.0.0.1", 5260, true);
```

---

### Key

The Key class can be used to generate a key.

There are two key types that can be generated currently, more are planned and will be implemented into Activeledger first. These types are RSA and Elliptic Curve.

#### Generating a key

When generating a key the default is an Elliptic Curve key. The object returned will be a KeyIdentity class.

##### Example

```php
require __DIR__ . '/vendor/autoload.php';

// Generate Elliptic Key
$identity = activeledger\sdk\Key::generateKeyIdentity();

// Generate RSA Key
$identity = activeledger\sdk\Key::generateKeyIdentity("rsa");
```

#### Onboarding a key

Once you have a key generated, to use it to sign transactions it must be onboarded to the ledger network

##### Example

```php
require __DIR__ . '/vendor/autoload.php';

// Create Connection
$connection = new activeledger\sdk\Connection("http", "127.0.0.1", 5260, false);

// Generate Key
$identity = activeledger\sdk\Key::generateKeyIdentity();

try {
    // Onboard Key
    $stream = $identity->onBoard($connection);
}catch(Exception $error) {
    // Manage any exceptions such as consensus problem or transport errors
    die($error->getMessage());
}
```

#### Exporting Key

To save the key for later use you can use the php serialize function

```php
require __DIR__ . '/vendor/autoload.php';

// Generate Key
$identity = activeledger\sdk\Key::generateKeyIdentity();

// Store object as a safe string
$export = base64_encode(serialize($identity));
```

#### Importing Key

You can import a key using php unserialize function which restores the object

```php
require __DIR__ . '/vendor/autoload.php';

// Restore KeyIdentity Object from the exported safe string
$identity = serialize(base64_decode($export))
```

---

### Transaction

The Transaction class contains a static function which helps build an Activeledger transaction object.

```php
require __DIR__ . '/vendor/autoload.php';

// Generate Activeledger Transaction
$transaction = activeledger\sdk\Transaction::build(
    "Contract Stream / Label",
    "Namespace",
    // Input Streams (Requires Signatures)
    array("Identity Stream" => array()),
    // Outputs
    array("Outputs: Identity Stream" => array()),
    // Read Only Streams
    array("Reads : Label" => "Idenity Stream")
);
```

#### Signing & sending a transaction

When signing a transaction you must send the finished version of it. No changes can be made after signing as this will cause the ledger to reject it.

The key must be one that has been successfully onboarded to the ledger which the transaction is being sent to.

##### Example

```php
require __DIR__ . '/vendor/autoload.php';

// Create Connection
$connection = new activeledger\sdk\Connection("http", "127.0.0.1", 5260, false);

// Generate Key
$identity = activeledger\sdk\Key::generateKeyIdentity();

try {
    // Onboard Key
    $stream = $identity->onBoard($connection);

    // Generate Activeledger Transaction
    $transaction = activeledger\sdk\Transaction::build(
        "0000482232bcca98e3f2b375e6209400e185fae26efad7812268d7d66b321131",
        "example-namespace",
        // Input Streams (Requires Signatures)
        array($stream => array("text" => "Hello World"))
    );

    // Get signed version of this transaction
    $signedTx = $identity->sign($transaction)

    // Submit
    $response = $connection->send($signedTx);

    // Response object will contain the streams property.
    $response->streams->new; // Contains created Activity Streams
    $response->streams->updated; // Contains updated Activity Streams

}catch(Exception $error) {
    // Manage any exceptions such as consensus problem or transport errors
    die($error->getMessage());
}
```

## License

---

This project is licensed under the [MIT](https://github.com/activeledger/activeledger/blob/master/LICENSE) License
