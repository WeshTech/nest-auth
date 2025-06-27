import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { UsersService } from 'src/users/users.service';

@Injectable()
export class AuthService {
  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  getJwtSecret() {
    return this.configService.get<string>('JWT_SECRET');
  }

  async signIn(username: string, pass: string): Promise<any> {
    const user = await this.usersService.findOne(username);
    if (user?.password !== pass) {
      throw new UnauthorizedException('Invalid credentials!');
    }
    const { password, ...result } = user;

    //generate a jwt and return it here
    const payload = {
      sub: user.userId,
      username: user.username,
    };

    const access_token = await this.jwtService.signAsync(payload);

    return { access_token: access_token, user: result };
  }
}
