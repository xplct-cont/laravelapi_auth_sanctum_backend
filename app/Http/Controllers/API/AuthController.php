<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Request as HttpFoundationRequest;

class AuthController extends Controller
{
    public function register(Request $request){
           $request->validate([
            'name' => 'string|required',
            'password' => 'string|required',
            'email' => 'email|required',

           ]);

            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => bcrypt($request->password),
            ]);

            Auth::login($user);

            $token = $user->createToken('API')->plainTextToken;


            return response()->json([
                'status'=>'success',
                'message'=>'User registered successfully',
                'user'=>$user,
                'authentication'=> [
                    'token'=>$token, 
                    'type' =>'bearer',
                ]
            ]);
    }

    public function login(Request $request){
        $request->validate([
            'email' => 'email|required',
            'password' => 'string|required',
        ]);

        $login = Auth::attempt(
            $request->only('email', 'password')
        );   

        if(!$login){
            return response()->json([
                'status' => 'error',
                'message' => 'Invalid User Credentials',
            ], Response::HTTP_UNAUTHORIZED);
        }

        $user = Auth::user();
        $token = $user->createToken('API')->plainTextToken;
        
        return response()->json([
           'status' => 'success',
           'message' => 'User logged in successfully',
           'user' => $user,
                'authentication'=> [
                'token'=>$token, 
                'type' =>'bearer',
          ]
        ]);

    }

    public function logout(){
        Auth::user()->tokens()->delete();
        return response()->json([
            'status' => 'success',
            'message' => 'User logged out successfully'
        ]); 
    }


}
