<?php
/* Copyright (c) Rhapsody Project
 *
 * Licensed under the MIT License (http://opensource.org/licenses/MIT)
 *
 * Permission is hereby granted, free of charge, to any
 * person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the
 * Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice
 * shall be included in all copies or substantial portions of
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
 * KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
 * OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
namespace Rhapsody\SecurityBundle\Security\Jwt\KeyLoader;

/**
 * Load crypto keys for the OpenSSL crypto engine.
 */
class OpenSSLKeyLoader extends AbstractKeyLoader
{

    /**
     *
     * {@inheritdoc}
     *
     * @throws \RuntimeException If the key cannot be read
     * @throws \RuntimeException Either the key or the passphrase is not valid
     */
    public function loadKey($type)
    {
        $path = $this->getKeyPath($type);
        $encryptedKey = file_get_contents($path);
        $key = call_user_func_array(sprintf('openssl_pkey_get_%s', $type), self::TYPE_PRIVATE == $type ? [
                $encryptedKey,
                $this->getPassphrase()] : [$encryptedKey]);

        if (! $key) {
            throw new \RuntimeException(sprintf('Failed to load %1$s key "%2$s". Did you correctly set the "rhapsody_security.jwt.%1$s_key_path" config option?', $type, $path));
        }
        return $key;
    }

}
