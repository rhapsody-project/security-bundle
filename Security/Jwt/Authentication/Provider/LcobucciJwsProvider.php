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

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\ValidationData;
use Rhapsody\SecurityBundle\Security\Jwt\Authentication\Signature\JsonWebSignature;

class LcobucciJwsProvider extends AbstractJwsProvider implements JwsProviderInterface
{

    protected function createJwsBuilder()
    {
        return new Builder();
    }
    /**
     * {@inheritdoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\Authentication\Provider\JwsProviderInterface::create()
     */
    public function create(array $payload = array())
    {
        $builder = $this->createJwsBuilder()
                 ->issuedAt(time())
                 ->expiresAt(time() + $this->ttl);

        foreach ($payload as $name => $value) {
            $builder->with($name, $value);
        }

        try {
            $key = new Key($this->keyLoader->loadKey('private'), $this->keyLoader->getPassphrase());
            $builder->sign($this->signer, $key);
            $signed = true;
        }
        catch (\InvalidArgumentException $e) {
            $signed = false;
        }

        $signature = new JsonWebSignature((string) $builder->getToken(), $signed);
        return $signature;
    }

    /**
     * {@inheritdoc}
     * @see \Rhapsody\SecurityBundle\Security\Jwt\Authentication\Provider\JwsProviderInterface::load()
     */
    public function load($token)
    {
        $tokenParser = new Parser();
        $jws = $tokenParser->parse((string) $token);

        $payload = array();
        foreach ($jws->getClaims() as $claim) {
            $payload[$claim->getName()] = $claim->getValue();
        }

        $verified = $jws->verify($this->signer, $this->keyLoader->loadKey('public'));

        $signature = new JsonWebSignature($token, true);
        $signature->update($payload, $verified && $jws->validate(new ValidationData()));
        return $signature;
    }

    protected function getSignerForAlgorithm($signatureAlgorithm)
    {
        if (0 === strpos($signatureAlgorithm, 'HS')) {
            $signerType = 'Hmac';
        } elseif (0 === strpos($signatureAlgorithm, 'RS')) {
            $signerType = 'Rsa';
        } elseif (0 === strpos($signatureAlgorithm, 'EC')) {
            $signerType = 'Ecdsa';
        }

        if (!isset($signerType)) {
            throw new \InvalidArgumentException(sprintf('The algorithm "%s" is not supported by %s', $signatureAlgorithm, __CLASS__));
        }

        $bits   = substr($signatureAlgorithm, 2, strlen($signatureAlgorithm));
        $signer = sprintf('Lcobucci\\JWT\\Signer\\%s\\Sha%s', $signerType, $bits);

        return new $signer();
    }

    protected function isAlgorithmSupportedForEngine($cryptoEngine, $signatureAlgorithm)
    {
        return true;
    }
}
