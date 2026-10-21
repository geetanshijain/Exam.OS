"""create_auth_and_security_schema

Revision ID: 6d493e1d1606
Revises: 
Create Date: 2026-10-11 20:49:31.173769

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6d493e1d1606'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create password_reset_tokens table
    op.create_table('password_reset_tokens',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(length=255), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_password_reset_tokens_expires_at'), 'password_reset_tokens', ['expires_at'], unique=False)
    op.create_index(op.f('ix_password_reset_tokens_id'), 'password_reset_tokens', ['id'], unique=False)
    op.create_index(op.f('ix_password_reset_tokens_token_hash'), 'password_reset_tokens', ['token_hash'], unique=False)
    op.create_index(op.f('ix_password_reset_tokens_user_id'), 'password_reset_tokens', ['user_id'], unique=False)

    # 2. Create user_sessions table
    op.create_table('user_sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('session_id', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token_jti', sa.String(length=64), nullable=False),
        sa.Column('ip_address', sa.String(length=100), nullable=True),
        sa.Column('user_agent', sa.String(length=500), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_sessions_expires_at'), 'user_sessions', ['expires_at'], unique=False)
    op.create_index(op.f('ix_user_sessions_id'), 'user_sessions', ['id'], unique=False)
    op.create_index(op.f('ix_user_sessions_session_id'), 'user_sessions', ['session_id'], unique=True)
    op.create_index(op.f('ix_user_sessions_token_jti'), 'user_sessions', ['token_jti'], unique=False)
    op.create_index(op.f('ix_user_sessions_user_id'), 'user_sessions', ['user_id'], unique=False)

    # 3. Add department column to question_papers
    with op.batch_alter_table('question_papers', schema=None) as batch_op:
        batch_op.add_column(sa.Column('department', sa.String(length=100), nullable=False, server_default='General'))
        batch_op.create_index(batch_op.f('ix_question_papers_department'), ['department'], unique=False)

    # 4. Add security & profile columns to users
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('username', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('department', sa.String(length=100), nullable=False, server_default='General'))
        batch_op.add_column(sa.Column('mfa_enabled', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column('mfa_secret', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('recovery_codes_json', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('locked_until', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.alter_column('hashed_password',
            existing_type=sa.VARCHAR(length=255),
            type_=sa.String(length=500),
            existing_nullable=False
        )

    # Populate distinct usernames for existing rows before adding unique index
    op.execute("UPDATE users SET username = substr(email, 1, instr(email, '@') - 1) WHERE username IS NULL")
    op.execute("UPDATE users SET updated_at = created_at WHERE updated_at IS NULL")

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column('username', nullable=False)
        batch_op.create_index(batch_op.f('ix_users_username'), ['username'], unique=True)


def downgrade() -> None:
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_username'))
        batch_op.drop_column('updated_at')
        batch_op.drop_column('locked_until')
        batch_op.drop_column('failed_login_attempts')
        batch_op.drop_column('recovery_codes_json')
        batch_op.drop_column('mfa_secret')
        batch_op.drop_column('mfa_enabled')
        batch_op.drop_column('department')
        batch_op.drop_column('username')

    with op.batch_alter_table('question_papers', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_question_papers_department'))
        batch_op.drop_column('department')

    op.drop_table('user_sessions')
    op.drop_table('password_reset_tokens')
