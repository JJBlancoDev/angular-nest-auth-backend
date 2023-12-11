import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JWTPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor( 
    private jwtService: JwtService, 
    private authService: AuthService
  ) {}


  async canActivate( context: ExecutionContext ): Promise<boolean> {
    const request = context.switchToHttp().getRequest(); // Se toma la request de la petición
    const token = this.extractTokenFromHeader(request); 

    if (!token) {
      throw new UnauthorizedException("Se esperaba un token de usuario en la petición");
    }

    try {
      const payload = await this.jwtService.verifyAsync<JWTPayload>(
        token, { secret: process.env.JWT_SEED }
      );

      const user = await this.authService.findUserById( payload.id );
      if(!user) throw new UnauthorizedException("No existe el usario");
      if(!user.isActive) throw new UnauthorizedException("El usuario no esta activo");

      request['user'] = user;

    } catch (error) {
      throw new UnauthorizedException();
    }
    
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
