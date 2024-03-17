import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { jwtConstants } from './auth.constants';
import { Request } from 'express';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException();
    }

    try {
      const payload = await this.jwtService.verifyAsync(token, {
        secret: jwtConstants.secret,
      });
      request['user'] = payload;
    } catch {
      throw new UnauthorizedException();
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    let token: string;

    if (
      request.headers.authorization &&
      request.headers.authorization.split(' ')[0] === 'Bearer'
    ) {
      token = request.headers.authorization.split(' ')[1];
    } else if (request.cookies && request.cookies['token']) {
      token = request.cookies['token'];
    } else {
      throw new HttpException('Token not found', HttpStatus.BAD_REQUEST);
    }

    return token;
  }
}
