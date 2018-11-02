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
 * Handles the Transaction objects sent to Activeledger
 *
 */
class Transaction
{
    /**
     * Builds an Activeledger Transaction Object
     *
     * @param string  $contract  Smart Contract Stream id or label name
     * @param string  $namespace Namespace which holds the Smart Contract
     * @param array   $inputs    Activity Stream Identity inputs
     * @param array   $outputs   Activity Stream Identity inputs
     * @param array   $readonly  Additional Activity Streams for read only purpose
     * @param boolean $selfsign  Is this transaction self signed
     * 
     * @return object
     */
    public static function build(
        $contract,
        $namespace,
        $inputs = array(),
        $outputs = array(),
        $readonly = array(),
        $selfsign = false
    ) {

        // Prebuild $sigs array from $inputs
        $sigs = array();
        $inputKeys = array_keys($inputs);
        foreach ($inputKeys as $key) {
            $sigs[$key] = "";
        }

        // Transaction Object
        return array(
            '$tx' => array(
                '$contract' => $contract,
                '$namespace' => $namespace,
                '$i' => $inputs,
                '$o' => $outputs,
                '$r' => $readonly
            ),
            '$sigs' => $sigs,
            '$selfsign' => $selfsign
        );
    }
}
