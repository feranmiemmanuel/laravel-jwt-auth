<?php

namespace App\Http\Controllers;

use Carbon\Carbon;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use PHPOpenSourceSaver\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }
    public function register(Request $request)
    {
        $validator = Validator::make(
            $request->all(),[
                'user_id' => uniqid('USR-'),
                'name' => 'required',
                'email' => 'required|string|email|unique:users',
                'password' => 'required|string|confirmed|min:6'
            ]);
        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => $validator->errors()->first()], 400);
        }
        $user = new User();
        $user->user_id = uniqid('USR-');
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = Hash::make($request->password);
        $user->save();
        return response()->json([
            'success' => true,
            'message' => 'User Registration is completed successfully',
            'user' => $user
        ], 201);
    }
    public function login(Request $request)
    {
        $validator = Validator::make(
            $request->all(),[
                'email' => 'required|email',
                'password' => 'required|string|min:6'
            ]);
        if ($validator->fails()) {
            return response()->json(['success' => false, 'message' => $validator->errors()->first()], 422);
        }
        $credentials = $request->only('email', 'password');
        if (!$token = auth()->attempt($credentials, ['exp' => Carbon::now()->addDays(14)->timestamp])) {
            return response()->json(['success' => false, 'message' => 'Unauthorized'], 401);
        }
        return $this->createToken($token);
    }
    public function createToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL()*60,
            'user' => auth()->user()
        ]);
    }
}
