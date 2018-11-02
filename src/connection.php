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
 * Handles the Activeledger Node Connection
 *
 */
class Connection
{
    /**
     * Node URL
     *
     * @var string
     */
    private $_url;

    /**
     * Node Public PEM
     *
     * @var string
     */
    private $_pem;

    /**
     * Request Headers (Encrypt or Normal)
     *
     * @var array
     */
    private $_headers;

    /**
     * Create Activeledger Connection Object
     *
     * @param string  $protocol http | https
     * @param string  $address  location
     * @param int     $port     port
     * @param boolean $encrypt  Encrypted Transactios?
     */
    public function __construct($protocol, $address, $port, $encrypt)
    {
        // Build Connection Url
        $this->_url = $protocol."://".$address.":".$port;

        // Setup Headers
        $this->_headers = array(
            "Content-type: application/json"
        );

        if ($encrypt) {
            // Fetch Nodes Public Key
            $this->_pem = base64_decode($this->_getStatus()->pem);

            // Modify Headers For Encrypt
            $this->_headers[0] = "Content-type: plain/text";
            $this->_headers[] = "X-Activeledger-Encrypt: 1";
        }
    }

    /**
     * Get Nodes status
     *
     * @return object
     */
    private function _getStatus()
    {
        return json_decode(
            file_get_contents($this->_url."/a/status")
        );
    }

    /**
     * Makes the HTTP request to send transaction
     *
     * @param string $content string posted to Activeledger
     *
     * @return object
     */
    private function _submit($content)
    {
        // Build Request Context
        $context = stream_context_create(
            array(
            'http' => array(
                'method' => 'POST',
                'header' => $this->_headers,
                'content' => $content,
                'timeout' => 60
                )
             )
        );
        
        // Send Request & Get Response or Manage Error
        if (!$response = file_get_contents($this->_url, false, $context)) {
            // Get The Last Error
            $error = error_get_last();

            // Make Friendly Message
            $message = substr($error['message'], strpos($error['message'], ": ") + 2);

            // Throw Error
            throw new \Exception($message);
        }

        // return response
        return json_decode($response);
    }

    /**
     * Send Transaction to Activeledger Network
     *
     * @param object $txBody Activeledger Transaction Object
     *
     * @return object
     */
    public function send($txBody)
    {
        // Encrypted Connection?
        if ($this->_pem) {
            // Encrypt with the nodes public address
            openssl_public_encrypt(
                json_encode($txBody, JSON_UNESCAPED_SLASHES),
                $encrypted,
                $this->_pem,
                OPENSSL_PKCS1_OAEP_PADDING
            );

            // Submit Transaction as Base54 Encoded body
            return $this->_submit(base64_encode($encrypted));
        }

        // Normal Transaction Send as JSON
        $response = $this->_submit(json_encode($txBody, JSON_UNESCAPED_SLASHES));
        
        // Did we get a response?
        if ($response && $response->{'$umid'}) {
            // Transform response to be php friendly
            $transform = new \stdClass;
            $transform->umid = $response->{'$umid'};
            $transform->summary = $response->{'$summary'};

            // Debug Mode Enabled?
            if ($response->{'$debug'}) {
                $transform->debug = $response->{'$debug'};
            }

            // Do we have errors?
            // Without commits (Only 1 node may error)
            if (isset($transform->summary->errors) && $transform->summary->commit == 0) {
                // Throw First Error
                throw new \Exception($transform->summary->errors[0]);
            }

            // Make sure we have streams
            if ($response->{'$streams'}) {
                $transform->streams = $response->{'$streams'};
            }
            
            return $transform;
        }
        
        return false;
    }
}
