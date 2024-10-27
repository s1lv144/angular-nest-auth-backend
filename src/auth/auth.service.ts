import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';
import { OAuth2Client } from 'google-auth-library';

import * as bcryptjs from 'bcryptjs';

import { RegisterUserDto, CreateUserDto, UpdateAuthDto, LoginDto } from './dto';

import { User } from './entities/user.entity';

import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {
  private client: OAuth2Client;
  constructor(
   
    @InjectModel( User.name ) 
    private userModel: Model<User>,

    private jwtService: JwtService,
    
   
   ) {
    this.client = new OAuth2Client('719230093554-a2j4ksbdcg1rm81k1oj6sg2rg9snbets.apps.googleusercontent.com');
  
   }
   
  
  async create(createUserDto: CreateUserDto): Promise<User> {
    
    try {
      
      const { password, ...userData } = createUserDto;
           
      const newUser = new this.userModel({
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      });

       await newUser.save();
       const { password:_, ...user } = newUser.toJSON();
       
       return user;
      
    } catch (error) {
      if( error.code === 11000 ) {
        throw new BadRequestException(`${ createUserDto.email } already exists!`)
      }
      throw new InternalServerErrorException('Something terribe happen!!!');
    }

  }

  async register( registerDto: RegisterUserDto ): Promise<LoginResponse> {

    const user = await this.create( registerDto );

    return {
      user: user,
      token: this.getJwtToken({ id: user._id })
    }
  }


  async login( loginDto: LoginDto ):Promise<LoginResponse> {

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email });
    if ( !user ) {
      throw new UnauthorizedException('Not valid credentials - email');
    }
    
    if ( !bcryptjs.compareSync( password, user.password ) ) {
      throw new UnauthorizedException('Not valid credentials - password');
    }

    const { password:_, ...rest  } = user.toJSON();

      
    return {
      user: rest,
      token: this.getJwtToken({ id: user.id }),
    }
  
  }


  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById( id: string ) {
    const user = await this.userModel.findById( id );
    const { password, ...rest } = user.toJSON();
    return rest;
  }


  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken( payload: JwtPayload ) {
    const token = this.jwtService.sign(payload);
    return token;
  }
  async verifyGoogleToken(token: string) {
    const ticket = await this.client.verifyIdToken({
      idToken: token,
      audience: '719230093554-a2j4ksbdcg1rm81k1oj6sg2rg9snbets.apps.googleusercontent.com',  // Especifica tu CLIENT_ID de Google aquí
    });
    const payload = ticket.getPayload();
    
    return payload; // Aquí tienes la información del usuario autenticado
  }

  /*async loginWithGoogle(token: string): Promise<LoginResponse> {
    /*let newUser;
    const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    
    // Verifica si el usuario ya existe en la base de datos
    const user = await this.userModel.findOne({ email: payload.email });
    if (!user) {
      // Si no existe, lo creas
     newUser = new this.userModel({
        email: payload.email,
        name: payload.name,
        googleId: payload.sub,
        // Otras propiedades que quieras guardar
      });
      await newUser.save();
    }
    
    // Si existe o fue creado, generas el token JWT
    return {
      user: user || newUser,
      token: this.getJwtToken({ id: user ? user.id : newUser.id }),
    };
  }*/

}//fin de la clase
