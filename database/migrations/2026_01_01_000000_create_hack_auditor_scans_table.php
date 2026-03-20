<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('hack_auditor_scans', function (Blueprint $table): void {
            $table->ulid('id')->primary();
            $table->integer('score');
            $table->integer('total_vulnerabilities');
            $table->integer('critical_count')->default(0);
            $table->integer('high_count')->default(0);
            $table->integer('medium_count')->default(0);
            $table->integer('low_count')->default(0);
            $table->json('vulnerabilities');
            $table->text('summary');
            $table->integer('files_scanned');
            $table->integer('scan_duration_ms');
            $table->string('ai_provider')->nullable();
            $table->string('ai_model')->nullable();
            $table->string('laravel_version');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('hack_auditor_scans');
    }
};
