<?php
/**
 * MIT License (MIT)
 * Copyright (c) 2018 Activeledger
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace activeledger\sdk;

/**
 * Key Handler
 */
class Key
{
    /**
     * Generate a new Public Private Key Pair
     *
     * @param string $type rsa | ec
     *
     * @return KeyIdentity
     */
    public static function generateKeyIdentity($type="ec")
    {
        // Default RSA
        $config = array(
            'digest_alg' => 'sha256',
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        );

        // Creating EC Key?
        if ($type == "ec") {
            $config = array(
                "digest_alg" => "sha256",
                "private_key_type" => OPENSSL_KEYTYPE_EC,
                "curve_name" => "secp256k1"
            );
            // Update Type
            $type = "secp256k1";
        }

            
        // Create the private and public key
        $res = openssl_pkey_new($config);
        
        // Extract the private key from $res to $privKey
        openssl_pkey_export($res, $privateKey);
        
        // Extract the public key from $res to $pubKey
        $pubKey = openssl_pkey_get_details($res);

        // Key Object
        $key = new KeyIdentity($pubKey["key"], $privateKey, "identity", $type);

        // Return KeyDetail Object
        return $key;
    }
}

/**
 * Holds Public Private Key Properties
 */
class KeyIdentity
{
    /**
     * Public Key PEM Format
     *
     * @var string
     */
    private $_publicKey;

    /**
     * Private Key PEM Format
     *
     * @var string
     */
    private $_privateKey;

    /**
     * Activeledger Identity (Stream Id)
     *
     * @var string
     */
    private $_identity;

    /**
     * Key Type Hint
     *
     * @var string
     */
    private $_type;

    /**
     * Construct Key Identity
     *
     * @param string $public   Public Key PEM
     * @param string $private  Private Key PEM
     * @param string $identity Activity Stream Id
     * @param string $type     Hint the type of key (rsa | ec)
     */
    public function __construct($public, $private = "", $identity = "", $type = "rsa")
    {
        $this->_publicKey = $public;
        $this->_privateKey = $private;
        $this->_identity = $identity;
        $this->_type = $type;
    }

    /**
     * Run default Activeledger onboard contract for this identity
     *
     * @param Connection $connection Activeledger Connection
     *
     * @return void
     */
    public function onBoard($connection)
    {

        // Build Transaction Object
        $transaction = Transaction::build(
            "onboard",
            "default",
            array(
                $this->_identity =>
                    array(
                        'publicKey' => $this->_publicKey,
                        'type' => strtolower($this->_type)
                    )
                    ),
            array(),
            array(),
            true
        );

        // Sign & Send Transaction
        $results = $connection->send($this->sign($transaction));

        // Succuesfull Transaction
        if ($results->streams) {
            // Set Identity
            $this->_identity = $results->streams->new[0]->id;
        }
        
        // Return Identity
        return $this->_identity;
    }

    /**
     * Sign string data with identity's private key
     *
     * @param string $sign string data to be signed
     *
     * @return string
     */
    public function signString($sign)
    {
        // Sign $tx object
        openssl_sign($sign, $signature, $this->_privateKey, OPENSSL_ALGO_SHA256);

        // Return full signed transaction object
        return $signature;
    }

    /**
     * Return Signed Transaction with this identity
     *
     * @param object $transaction Activeledger Transaction Object
     *                            From Transaction::build
     *
     * @return object
     */
    public function sign($transaction)
    {
        // Basic Transaction Check
        if ($transaction['$tx']) {
            
            // Add Signature to transaction
            $transaction['$sigs'][$this->_identity] = base64_encode(
                $this->signString(
                    json_encode(
                        $transaction['$tx'],
                        JSON_UNESCAPED_SLASHES
                    )
                )
            );

            // Return full signed transaction object
            return $transaction;
        }

        // Throw Error
        throw new \Exception('$tx property not found');
    }
}
