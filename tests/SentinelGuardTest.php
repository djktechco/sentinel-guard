<?php

namespace Rojtjo\SentinelGuard;

use PHPUnit\Framework\TestCase;
use Prophecy\PhpUnit\ProphecyTrait;
use Prophecy\Prophecy\ObjectProphecy;
use Cartalyst\Sentinel\Users\UserRepositoryInterface;
use Cartalyst\Sentinel\Persistences\PersistenceRepositoryInterface;

class SentinelGuardTest extends TestCase
{

    use ProphecyTrait;

    /**
     * @var GuardableSentinel|ObjectProphecy
     */
    private $sentinel;

    /**
     * @var SentinelGuard
     */
    private $subject;

    public function setUp(): void
    {
        $this->sentinel = $this->prophesize(GuardableSentinel::class);
        $this->subject  = new SentinelGuard(
            $this->sentinel->reveal()
        );
    }

    /** @test */
    public function check_via_remember()
    {
        $persistenceRepo = $this->prophesize(PersistenceRepositoryInterface::class);
        $persistenceRepo->check()->willReturn('123')->shouldBeCalled();
        $user = $this->fakeUser();
        $persistenceRepo->findUserByPersistenceCode('123')->willReturn($user)->shouldBeCalled();
        $this->sentinel->doCycleCheckpoints('check', $user)->willReturn(true)->shouldBeCalled();
        $this->sentinel->getPersistenceRepository()->willReturn($persistenceRepo->reveal())->shouldBeCalled();
        $this->sentinel->getUser()->willReturn(null)->shouldBeCalled();

        $this->assertTrue($this->subject->check());
        $this->assertTrue($this->subject->viaRemember());
    }

    /** @test */
    public function guest()
    {
        $this->sentinel->guest()->willReturn(true)->shouldBeCalled();

        $this->assertTrue($this->subject->guest());
    }

    /** @test */
    public function user()
    {
        $user = $this->fakeUser();
        $this->sentinel->getUser()->willReturn($user)->shouldBeCalled();

        $result = $this->subject->user();

        $this->assertEquals($user, $result);
    }

    /** @test */
    public function id_when_logged_in()
    {
        $user = $this->fakeUser();
        $this->sentinel->getUser()->willReturn($user)->shouldBeCalled();

        $result = $this->subject->id();

        $this->assertEquals(123, $result);
    }

    /** @test */
    public function id_as_guest()
    {
        $this->sentinel->getUser()->willReturn(null)->shouldBeCalled();

        $result = $this->subject->id();

        $this->assertNull($result);
    }

    /** @test */
    public function validate_with_correct_credentials()
    {
        $credentials = $this->fakeCredentials();
        $userRepo    = $this->prophesize(UserRepositoryInterface::class);
        $this->sentinel->getUserRepository()->willReturn($userRepo->reveal())->shouldBeCalled();
        $user = $this->fakeUser();
        $userRepo->findByCredentials($credentials)->willReturn($user)->shouldBeCalled();
        $userRepo->validateCredentials($user, $credentials)->willReturn(true)->shouldBeCalled();

        $result = $this->subject->validate($credentials);

        $this->assertTrue($result);
    }

    /** @test */
    public function validate_with_incorrect_credentials()
    {
        $credentials = $this->fakeCredentials();
        $userRepo    = $this->prophesize(UserRepositoryInterface::class);
        $this->sentinel->getUserRepository()->willReturn($userRepo->reveal())->shouldBeCalled();
        $userRepo->findByCredentials($credentials)->willReturn(null)->shouldBeCalled();

        $result = $this->subject->validate($credentials);

        $this->assertFalse($result);
    }

    /** @test */
    public function set_user()
    {
        $user = $this->fakeUser();
        $this->sentinel->setUser($user)->shouldBeCalled();

        $this->subject->setUser($user);
    }

    /** @test */
    public function attempt_without_remember()
    {
        $credentials = $this->fakeCredentials();
        $this->sentinel->authenticate($credentials, false)->willReturn(true)->shouldBeCalled();

        $result = $this->subject->attempt($credentials);

        $this->assertTrue($result);
    }

    /** @test */
    public function attempt_with_remember()
    {
        $credentials = $this->fakeCredentials();
        $this->sentinel->authenticate($credentials, true)->willReturn(true)->shouldBeCalled();

        $result = $this->subject->attempt($credentials, true);

        $this->assertTrue($result);
    }

    /** @test */
    public function _once()
    {
        $credentials = $this->fakeCredentials();
        $this->sentinel->stateless($credentials)->willReturn(true)->shouldBeCalled();

        $result = $this->subject->once($credentials);

        $this->assertTrue($result);
    }

    /** @test */
    public function login_without_remember()
    {
        $user = $this->fakeUser();
        $this->sentinel->login($user, false)->shouldBeCalled();

        $this->subject->login($user);
    }

    /** @test */
    public function login_with_remember()
    {
        $user = $this->fakeUser();
        $this->sentinel->login($user, true)->shouldBeCalled();

        $this->subject->login($user, true);
    }

    /** @test */
    public function login_using_id_non_existing_user()
    {
        $userRepo = $this->prophesize(UserRepositoryInterface::class);
        $this->sentinel->getUserRepository()->willReturn($userRepo->reveal())->shouldBeCalled();
        $userRepo->findById(456)->willReturn(null)->shouldBeCalled();

        $result = $this->subject->loginUsingId(456);

        $this->assertFalse($result);
    }

    /** @test */
    public function login_using_id_existing_user_without_remember()
    {
        $userRepo = $this->prophesize(UserRepositoryInterface::class);
        $this->sentinel->getUserRepository()->willReturn($userRepo->reveal())->shouldBeCalled();
        $user = $this->fakeUser();
        $userRepo->findById(123)->willReturn($user)->shouldBeCalled();
        $this->sentinel->login($user, false)->shouldBeCalled();

        $result = $this->subject->loginUsingId(123);

        $this->assertEquals($user, $result);
    }

    /** @test */
    public function login_using_id_existing_user_with_remember()
    {
        $userRepo = $this->prophesize(UserRepositoryInterface::class);
        $this->sentinel->getUserRepository()->willReturn($userRepo->reveal())->shouldBeCalled();
        $user = $this->fakeUser();
        $userRepo->findById(123)->willReturn($user)->shouldBeCalled();
        $this->sentinel->login($user, true)->shouldBeCalled();

        $result = $this->subject->loginUsingId(123, true);

        $this->assertEquals($user, $result);
    }

    /** @test */
    public function once_using_id_non_existing_user()
    {
        $userRepo = $this->prophesize(UserRepositoryInterface::class);
        $this->sentinel->getUserRepository()->willReturn($userRepo->reveal())->shouldBeCalled();
        $userRepo->findById(456)->willReturn(null)->shouldBeCalled();

        $result = $this->subject->onceUsingId(456);

        $this->assertFalse($result);
    }

    /** @test */
    public function once_using_id_existing_user()
    {
        $userRepo = $this->prophesize(UserRepositoryInterface::class);
        $this->sentinel->getUserRepository()->willReturn($userRepo->reveal())->shouldBeCalled();
        $user = $this->fakeUser();
        $userRepo->findById(123)->willReturn($user)->shouldBeCalled();
        $this->sentinel->stateless($user)->willReturn(true)->shouldBeCalled();

        $result = $this->subject->onceUsingId(123);

        $this->assertTrue($result);
    }

    /** @test */
    public function via_remember()
    {
        $result = $this->subject->viaRemember();

        $this->assertFalse($result);
    }

    /** @test */
    public function logout()
    {
        $this->sentinel->logout()->shouldBeCalled();

        $this->subject->logout();
    }

    /**
     * @return array
     */
    private function fakeCredentials()
    {
        return [
            'email'    => 'john.doe@example.com',
            'password' => '1234',
        ];
    }

    /**
     * @return User
     */
    private function fakeUser()
    {
        return tap(new User(), function (User $user) {
            $user->id = 123;
        });
    }
}
