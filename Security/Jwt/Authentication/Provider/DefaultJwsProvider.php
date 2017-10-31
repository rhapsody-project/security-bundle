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
namespace Rhapsody\SecurityBundle\Security\Jwt\Authentication\Provider;

use Namshi\JOSE\JWS;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Signature\JsonWebSignature;

/**
 *
 * @author sean.quinn
 */
class DefaultJwsProvider extends AbstractJwsProvider implements JwsProviderInterface
{

    /**
     * {@inheritdoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\Authentication\Provider\JwsProviderInterface::create()
     */
    public function create(array $payload = array())
    {
        $jws = new JWS(['alg' => $this->signatureAlgorithm], $this->cryptoEngine);
        $jws->setPayload($payload + ['exp' => (time() + $this->ttl),'iat' => time()]);

        $key = $this->keyLoader->loadKey('private');
        $jws->sign($key, $this->keyLoader->getPassphrase());

        $signature = new JsonWebSignature($jws->getTokenString(), $jws->isSigned());
        return $signature;
    }

    /**
     * {@inheritdoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\Authentication\Provider\JwsProviderInterface::load()
     */
    public function load($token)
    {
        $jws = JWS::load($token, false, null, $this->cryptoEngine);
        $verified = $jws->verify($this->keyLoader->loadKey('public'), $this->signatureAlgorithm);

        $signature = new JsonWebSignature($token, $jws->isSigned());
        $signature->update($jws->getPayload(), $verified);
        return $signature;
    }

    /**
     *
     * @param unknown $signatureAlgorithm
     * @return NULL
     */
    protected function getSignerForAlgorithm($signatureAlgorithm)
    {
        return null;
    }

    /**
     *
     * @param string $cryptoEngine
     * @param string $signatureAlgorithm
     * @return bool
     */
    protected function isAlgorithmSupportedForEngine($cryptoEngine, $signatureAlgorithm)
    {
        $signerClass = sprintf('Namshi\\JOSE\\Signer\\%s\\%s', $cryptoEngine, $signatureAlgorithm);
        return class_exists($signerClass);
    }
}
