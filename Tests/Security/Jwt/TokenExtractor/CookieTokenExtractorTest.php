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
namespace Rhapsody\SecurityBundle\Tests\Security\Jwt\TokenExtractor;

use PHPUnit\Framework\TestCase;
use Rhapsody\SecurityBundle\Security\Jwt\TokenExtractor\CookieTokenExtractor;
use Symfony\Component\HttpFoundation\Request;

/**
 */
class CookieTokenExtractorTest extends TestCase
{

    public function testExtract()
    {
        $extractor = new CookieTokenExtractor('BEARER');

        $request = new Request();
        $request->cookies->add(['BEARER' => 'testtoken']);
        $this->assertEquals('testtoken', $extractor->extract($request));
    }

    public function testExtractWhenTokenNotInCookie()
    {
        $extractor = new CookieTokenExtractor('BEARER');

        $request = new Request();
        $this->assertFalse($extractor->extract($request));
    }

    public function testExtractWhenTokenInCookieWithWrongName()
    {
        $extractor = new CookieTokenExtractor('BEARER');

        $request = new Request();
        $request->cookies->add(['BEAR' => 'testtoken']);
        $this->assertFalse($extractor->extract($request));
    }

}
