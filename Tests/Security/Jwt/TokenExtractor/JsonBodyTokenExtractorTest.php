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
use Rhapsody\SecurityBundle\Security\Jwt\TokenExtractor\JsonBodyTokenExtractor;
use Symfony\Component\HttpFoundation\Request;

/**
 */
class JsonBodyTokenExtractorTest extends TestCase
{

    private function setFieldValue(Request $request, $field, $value)
    {
        $reflectionProperty = new \ReflectionProperty(get_class($request), $field);
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($request, $value);
    }

    public function testExtract()
    {
        $expected = json_encode(['token' => 'testtoken']);
        $extractor = new JsonBodyTokenExtractor('token');

        $request = new Request();
        $this->setFieldValue($request, 'content', $expected);
        $this->assertEquals('testtoken', $extractor->extract($request));
    }

    public function testExtractWhenRequestBodyHasContentButNotToken()
    {
        $expected = json_encode(['foo' => 'bar']);
        $extractor = new JsonBodyTokenExtractor('token');

        $request = new Request();
        $this->setFieldValue($request, 'content', $expected);
        $this->assertFalse($extractor->extract($request));
    }

    public function testExtractWhenRequestBodyHasNoContent()
    {
        $extractor = new JsonBodyTokenExtractor('token');

        $request = new Request();
        $this->assertFalse($extractor->extract($request));
    }

    public function testExtractWhenRequestBodyHasNonJsonContent()
    {
        $extractor = new JsonBodyTokenExtractor('token');

        $request = new Request();
        $this->setFieldValue($request, 'content', 'foo');
        $this->assertFalse($extractor->extract($request));
    }

    public function testExtractWhenRequestBodyHasTokenUnderDifferentPropertyName()
    {
        $expected = json_encode(['jwt' => 'testtoken']);
        $extractor = new JsonBodyTokenExtractor('token');

        $request = new Request();
        $this->setFieldValue($request, 'content', $expected);
        $this->assertFalse($extractor->extract($request));
    }
}
