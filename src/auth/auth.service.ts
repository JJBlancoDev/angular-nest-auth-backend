import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from '@nestjs/jwt';

import * as bcriptjs from 'bcryptjs';

import { CreateUserDto } from './dto/create-user.dto';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { LoginDto } from './dto/login.dto';

import { User } from './entities/user.entity';
import { JWTPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto } from './dto/register.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>, 
    private jwtService: JwtService
  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      const { password, ...userData } = createUserDto;
      const newUser = new this.userModel({
        password: bcriptjs.hashSync( password, 10 ),
        ...userData
      });
      await newUser.save();
      const { password:_, ...user } = newUser.toJSON();
      return user;
    } catch (error) {
      if(error.code === 11000) {
        throw new BadRequestException(`${ createUserDto.email } already exists!`)
      }
      throw new InternalServerErrorException('Something terrible happen!!')
    }

  }

  async register( registerDto: RegisterUserDto ): Promise<LoginResponse> {

    const user = await this.create( registerDto );

    return {
      user: user,
      token: this.getJwtToken({ id: user._id })
    }

  }


  async login( loginDto: LoginDto ): Promise<LoginResponse> {
    const { email, password } = loginDto;
    const user = await this.userModel.findOne({ email })

    if( !user ){
      throw new UnauthorizedException('Las credenciales no son validas');
    }

    if( !bcriptjs.compareSync( password, user.password) ) {
      throw new UnauthorizedException('Las credenciales no son validas');
    }

    const { password:_, ...rest } = user.toJSON();

    return {
      user: rest,
      token: this.getJwtToken({ id: user.id})
    }

  }

  findAll() {
    return this.userModel.find();
  }
  
  async findUserById( id: string ) {
    const user = await this.userModel.findById( id );
    const { password, ...response} = user.toJSON();
    return response;
  }

  getJwtToken( payload: JWTPayload ) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
