import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterUserDto } from './dto/register.dto';
import { AuthGuard } from './guards/auth.guard';
import { User } from './entities/user.entity';
import { LoginResponse } from './interfaces/login-response';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('/login')
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post('/register')
  register(@Body() registerDto: RegisterUserDto) {
    return this.authService.register( registerDto );
  }

  @UseGuards( AuthGuard )
  @Get()
  findAll( @Request() request: Request ) {
    const user = request['user'];
    return this.authService.findUserById( user );
  }

  @UseGuards( AuthGuard )
  @Get('/check-token')
  checkToken( @Request() request: Request ): LoginResponse {
    const user = request['user'];
    console.log(user);
    return {
      user,
      token: this.authService.getJwtToken({ id: user._id })
    }
  }
}
